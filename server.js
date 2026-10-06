const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: false } });
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");

if (process.env.NODE_ENV === "production" && !process.env.JWT_SECRET)
  console.warn("WARNING: set JWT_SECRET in production.");

const dataDir = path.join(__dirname, "data");
require("fs").mkdirSync(dataDir, {recursive:true});
const db = new Database(path.join(dataDir, "mtalk.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL COLLATE NOCASE UNIQUE,
 password_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user1 INTEGER NOT NULL,
 user2 INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 UNIQUE(user1,user2),
 FOREIGN KEY(user1) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(user2) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 conversation_id INTEGER NOT NULL,
 sender_id INTEGER NOT NULL,
 body TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
 FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id,id);
`);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:["'self'"],
      scriptSrc:["'self'","https://cdn.socket.io"],
      styleSrc:["'self'"],
      connectSrc:["'self","ws:","wss:"],
      imgSrc:["'self'","data:"]
    }
  }
}));
app.use(express.json({limit:"32kb"}));

const authLimiter = rateLimit({windowMs:15*60*1000,max:30,standardHeaders:true,legacyHeaders:false});
const apiLimiter = rateLimit({windowMs:60*1000,max:180,standardHeaders:true,legacyHeaders:false});
app.use("/api/", apiLimiter);

function tokenFor(user){
  return jwt.sign({sub:user.id, username:user.username}, JWT_SECRET, {expiresIn:"7d"});
}
function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Требуется вход"});
  try { req.user=jwt.verify(h.slice(7),JWT_SECRET); next(); }
  catch { return res.status(401).json({error:"Сессия истекла"}); }
}
function normalizePair(a,b){ return a<b ? [a,b] : [b,a]; }
function getConversation(a,b){
  const [u1,u2]=normalizePair(a,b);
  return db.prepare("SELECT * FROM conversations WHERE user1=? AND user2=?").get(u1,u2);
}
function createConversation(a,b){
  const [u1,u2]=normalizePair(a,b);
  let c=getConversation(a,b);
  if(c) return c;
  try {
    const r=db.prepare("INSERT INTO conversations(user1,user2,created_at) VALUES(?,?,?)").run(u1,u2,Date.now());
    return db.prepare("SELECT * FROM conversations WHERE id=?").get(r.lastInsertRowid);
  } catch { return getConversation(a,b); }
}
function userById(id){ return db.prepare("SELECT id,username,created_at FROM users WHERE id=?").get(id); }
function member(c,userId){ return c && (c.user1===userId || c.user2===userId); }

app.post("/api/register", authLimiter, async (req,res)=>{
  const username=String(req.body.username||"").trim();
  const password=String(req.body.password||"");
  if(!/^[A-Za-z0-9_А-Яа-яЁё-]{3,20}$/.test(username))
    return res.status(400).json({error:"Ник: 3–20 символов; буквы, цифры, _ или -"});
  if(password.length<6 || password.length>128)
    return res.status(400).json({error:"Пароль должен быть от 6 до 128 символов"});
  const exists=db.prepare("SELECT id FROM users WHERE username=?").get(username);
  if(exists) return res.status(409).json({error:"Такой ник уже занят"});
  const passwordHash=await bcrypt.hash(password,12);
  const r=db.prepare("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)")
    .run(username,passwordHash,Date.now());
  const user=userById(r.lastInsertRowid);
  res.status(201).json({token:tokenFor(user),user});
});

app.post("/api/login", authLimiter, async (req,res)=>{
  const username=String(req.body.username||"").trim();
  const password=String(req.body.password||"");
  const u=db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if(!u || !(await bcrypt.compare(password,u.password_hash)))
    return res.status(401).json({error:"Неверный ник или пароль"});
  res.json({token:tokenFor(u),user:userById(u.id)});
});

app.get("/api/me",auth,(req,res)=>res.json({user:userById(req.user.sub)}));

app.get("/api/users",auth,(req,res)=>{
  const q=String(req.query.q||"").trim();
  if(!q) return res.json([]);
  const users=db.prepare("SELECT id,username FROM users WHERE username LIKE ? AND id<>? ORDER BY username LIMIT 20")
    .all("%"+q.replace(/[%_]/g,"\\$&")+"%",req.user.sub);
  res.json(users);
});

app.get("/api/chats",auth,(req,res)=>{
  const rows=db.prepare(`
    SELECT c.id,c.user1,c.user2,
      CASE WHEN c.user1=? THEN u2.username ELSE u1.username END AS username,
      (SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS last_message,
      (SELECT created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS last_time
    FROM conversations c
    JOIN users u1 ON u1.id=c.user1 JOIN users u2 ON u2.id=c.user2
    WHERE c.user1=? OR c.user2=?
    ORDER BY COALESCE(last_time,c.created_at) DESC
  `).all(req.user.sub,req.user.sub,req.user.sub);
  res.json(rows);
});

app.post("/api/chats",auth,(req,res)=>{
  const other=Number(req.body.userId);
  if(!Number.isInteger(other)||other===req.user.sub) return res.status(400).json({error:"Неверный пользователь"});
  if(!userById(other)) return res.status(404).json({error:"Пользователь не найден"});
  const c=createConversation(req.user.sub,other);
  res.json({id:c.id, user:userById(other)});
});

app.get("/api/chats/:id/messages",auth,(req,res)=>{
  const c=db.prepare("SELECT * FROM conversations WHERE id=?").get(Number(req.params.id));
  if(!member(c,req.user.sub)) return res.status(403).json({error:"Нет доступа"});
  const rows=db.prepare(`
    SELECT m.id,m.body,m.created_at,m.sender_id,u.username
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE m.conversation_id=? ORDER BY m.id DESC LIMIT 100
  `).all(c.id).reverse();
  res.json(rows);
});

app.get("/", (req,res) => res.type("html").send(INDEX_HTML));
app.get("/style.css", (req,res) => res.type("css").send(STYLE_CSS));
app.get("/app.js", (req,res) => res.type("application/javascript").send(APP_JS));


const INDEX_HTML = '<!doctype html><html lang="ru"><head>\n<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>M-Talk</title><link rel="stylesheet" href="style.css"></head><body>\n<div id="auth" class="auth"><div class="authbox"><div class="logo">M<span>-</span>Talk</div><div class="muted">Безопасный интернет-мессенджер</div>\n<div class="tabs"><button id="lt" class="active">Войти</button><button id="rt">Регистрация</button></div>\n<input id="un" placeholder="Ник"><input id="pw" type="password" placeholder="Пароль"><button id="ab">Войти</button><div id="err"></div></div></div>\n<div id="app" class="hidden">\n<header><div class="brand">M<span>-</span>Talk</div><div class="me" id="me"></div></header>\n<div class="layout"><aside><div class="search"><input id="search" placeholder="🔎  Поиск"></div><div id="results"></div><div class="section">Чаты</div><div id="chats"></div></aside>\n<section class="chat"><div id="empty" class="empty"><div>💬</div><b>Выберите чат</b><span>Найдите пользователя через поиск</span></div>\n<div id="chatbox" class="hidden"><div class="chathead"><div class="avatar" id="avatar">M</div><div><b id="ctitle"></b><small id="cstatus">был(а) недавно</small></div></div>\n<div id="msgs"></div><form id="form"><input id="body" autocomplete="off" placeholder="Сообщение"><button>➤</button></form></div></section></div></div>\n<script src="/socket.io/socket.io.js"></script><script src="app.js"></script></body></html>';
const STYLE_CSS = '*{box-sizing:border-box}body{margin:0;font-family:Arial,system-ui,sans-serif;background:#d9e5ef;color:#17212b}button,input{font:inherit}.hidden{display:none!important}\n.auth{min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#d9e5ef,#eef5f9)}.authbox{width:min(390px,92%);background:#fff;padding:30px;border-radius:18px;box-shadow:0 12px 45px #0002}.logo{font-size:40px;font-weight:800;text-align:center}.logo span,.brand span{color:#3390ec}.muted{color:#8493a2;text-align:center;margin:4px 0 24px}.tabs{display:flex;background:#edf2f6;border-radius:10px;padding:3px;margin-bottom:14px}.tabs button{width:50%;border:0;background:transparent;padding:10px;border-radius:8px;color:#71808e}.tabs .active{background:#fff;color:#2387df;box-shadow:0 1px 5px #0001}.authbox input{display:block;width:100%;padding:13px;margin:9px 0;border:1px solid #d5dfe8;border-radius:10px;outline:none}.authbox>#ab{width:100%;border:0;padding:13px;border-radius:10px;background:#3390ec;color:#fff;font-weight:bold;margin-top:5px}.authbox #err{text-align:center;color:#e04f5f;min-height:22px;margin-top:10px}\n#app{height:100vh;background:#fff}header{height:56px;background:#fff;border-bottom:1px solid #dfe6ec;display:flex;align-items:center;justify-content:space-between;padding:0 18px}.brand{font-weight:800;font-size:24px}.me{color:#657483}.layout{height:calc(100vh - 56px);display:flex;max-width:1200px;margin:auto}aside{width:350px;border-right:1px solid #dfe6ec;overflow:auto;background:#fff}.search{padding:10px}.search input{width:100%;padding:10px 13px;border:0;background:#f1f3f5;border-radius:10px;outline:0}.section{font-size:12px;text-transform:uppercase;color:#8a98a5;padding:12px 15px 7px}.person,.chatrow{display:flex;align-items:center;gap:11px;padding:10px 14px;cursor:pointer}.person:hover,.chatrow:hover{background:#f1f3f5}.chatrow.active{background:#e7f2fd}.avatar{width:45px;height:45px;border-radius:50%;background:#55a7e8;color:#fff;display:grid;place-items:center;font-weight:bold;flex:none}.chatrow .txt{min-width:0}.chatrow b{display:block}.chatrow small{display:block;color:#7b8995;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:3px}.chat{flex:1;min-width:0;background:#e6ebef;position:relative}.empty{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#6d7b87;gap:8px}.empty div{font-size:55px}.chathead{height:60px;background:#fff;display:flex;align-items:center;gap:10px;padding:7px 15px;border-bottom:1px solid #dce3e8}.chathead .avatar{width:42px;height:42px}.chathead small{display:block;color:#87939e;font-size:12px;margin-top:2px}.chathead b{font-size:15px}#msgs{height:calc(100% - 112px);overflow:auto;padding:18px;display:flex;flex-direction:column;gap:4px}.bubble{max-width:70%;padding:7px 10px;border-radius:10px;background:#fff;box-shadow:0 1px 1px #0001;align-self:flex-start}.bubble.mine{background:#e1ffc7;align-self:flex-end}.bubble p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.bubble small{font-size:10px;color:#7c898f;float:right;margin:5px 0 0 9px}form{height:52px;background:#fff;display:flex;gap:8px;padding:7px;border-top:1px solid #d9e1e7}form input{flex:1;border:0;background:#f0f2f4;border-radius:10px;padding:10px 13px;outline:0}form button{border:0;background:#3390ec;color:white;border-radius:10px;width:46px;font-size:20px}@media(max-width:700px){aside{width:100%}.chat{display:none}.layout.chatopen aside{display:none}.layout.chatopen .chat{display:block}.me{font-size:12px}}';
const APP_JS = 'let token=localStorage.getItem("mtalk_token"), me=null, socket=null, current=null, chats=[];\nconst $=x=>document.getElementById(x), esc=s=>String(s).replace(/[&<>"\']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\'":"&#039;"}[c]));\nasync function api(url,opt={}){opt.headers={...(opt.headers||{}),Authorization:"Bearer "+token,"Content-Type":"application/json"};const r=await fetch(url,opt);const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Ошибка");return d}\nlet mode="login";$("lt").onclick=()=>setMode("login");$("rt").onclick=()=>setMode("register");\nfunction setMode(m){mode=m;$("lt").classList.toggle("active",m==="login");$("rt").classList.toggle("active",m==="register");$("ab").textContent=m==="login"?"Войти":"Создать аккаунт";$("err").textContent=""}\n$("ab").onclick=async()=>{try{const r=await fetch("/api/"+(mode==="login"?"login":"register"),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("un").value.trim(),password:$("pw").value})});const d=await r.json();if(!r.ok)throw Error(d.error);token=d.token;localStorage.setItem("mtalk_token",token);await boot()}catch(e){$("err").textContent=e.message}};\nasync function boot(){if(!token)return;try{const d=await api("/api/me");me=d.user;$("me").textContent="👤 "+me.username;$("auth").classList.add("hidden");$("app").classList.remove("hidden");socket=io({auth:{token}});socket.on("message",m=>{if(current&&m.conversation_id===current.id)addMsg(m);loadChats()});socket.on("connect_error",()=>{});await loadChats()}catch{localStorage.removeItem("mtalk_token");token=null}}\nasync function loadChats(){chats=await api("/api/chats");$("chats").innerHTML=chats.map(c=>`<div class="chatrow ${current&&current.id===c.id?"active":""}" onclick="openChat(${c.id})"><div class="avatar">${esc(c.username[0].toUpperCase())}</div><div class="txt"><b>${esc(c.username)}</b><small>${esc(c.last_message||"Новый чат")}</small></div></div>`).join("")}\nwindow.openChat=async id=>{const c=chats.find(x=>x.id===id);if(!c)return;current={id:c.id,username:c.username};$("empty").classList.add("hidden");$("chatbox").classList.remove("hidden");$("ctitle").textContent=c.username;$("avatar").textContent=c.username[0].toUpperCase();$("msgs").innerHTML="";socket.emit("joinChat",id);const ms=await api("/api/chats/"+id+"/messages");ms.forEach(addMsg);scroll();loadChats()};\nfunction addMsg(m){const d=document.createElement("div");d.className="bubble "+(m.sender_id===me.id?"mine":"");d.innerHTML=`<p>${esc(m.body)}</p><small>${new Date(m.created_at).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})}</small>`;$("msgs").appendChild(d)}\nfunction scroll(){$("msgs").scrollTop=$("msgs").scrollHeight}\n$("form").onsubmit=e=>{e.preventDefault();const b=$("body").value.trim();if(b&&current){socket.emit("sendMessage",{chatId:current.id,body:b});$("body").value=""}};\nlet timer;$("search").oninput=()=>{clearTimeout(timer);timer=setTimeout(search,250)};async function search(){const q=$("search").value.trim();if(!q){$("results").innerHTML="";return}const us=await api("/api/users?q="+encodeURIComponent(q));$("results").innerHTML=us.map(u=>`<div class="person" onclick="startChat(${u.id})"><div class="avatar">${esc(u.username[0].toUpperCase())}</div><b>${esc(u.username)}</b></div>`).join("")}\nwindow.startChat=async uid=>{const c=await api("/api/chats",{method:"POST",body:JSON.stringify({userId:uid})});$("search").value="";$("results").innerHTML="";await loadChats();openChat(c.id)};\nif(token)boot();';

io.use((socket,next)=>{
  try {
    const raw=socket.handshake.auth?.token||"";
    socket.user=jwt.verify(raw,JWT_SECRET);
    next();
  } catch { next(new Error("AUTH_FAILED")); }
});

const online=new Map();

io.on("connection",socket=>{
  const uid=Number(socket.user.sub);
  if(!online.has(uid)) online.set(uid,new Set());
  online.get(uid).add(socket.id);
  io.emit("presence",{userId:uid,online:true});

  socket.on("joinChat",chatId=>{
    const c=db.prepare("SELECT * FROM conversations WHERE id=?").get(Number(chatId));
    if(member(c,uid)) socket.join("chat:"+c.id);
  });

  socket.on("sendMessage",payload=>{
    const chatId=Number(payload?.chatId);
    const body=String(payload?.body||"").trim();
    if(!body || body.length>4000) return;
    const c=db.prepare("SELECT * FROM conversations WHERE id=?").get(chatId);
    if(!member(c,uid)) return;
    const r=db.prepare("INSERT INTO messages(conversation_id,sender_id,body,created_at) VALUES(?,?,?,?)")
      .run(chatId,uid,body,Date.now());
    const m=db.prepare(`SELECT m.id,m.body,m.created_at,m.sender_id,u.username FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(r.lastInsertRowid);
    io.to("chat:"+chatId).emit("message",m);
  });

  socket.on("disconnect",()=>{
    const set=online.get(uid); if(set){set.delete(socket.id);if(!set.size){online.delete(uid);io.emit("presence",{userId:uid,online:false});}}
  });
});

server.listen(PORT,()=>console.log(`M-Talk v2: http://localhost:${PORT}`));
