const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

if (!process.env.JWT_SECRET) {
  console.warn("WARNING: set JWT_SECRET in production.");
}

fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });

const db = new Database(path.join(__dirname, "data", "mtalk.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user1 INTEGER NOT NULL,
  user2 INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(user1, user2),
  FOREIGN KEY(user1) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(user2) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  sender_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE,
  FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'", "ws:", "wss:"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
  })
);

app.use(express.json({ limit: "32kb" }));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

function makeToken(id) {
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";

  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Не авторизован" });
  }

  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Сессия истекла" });
  }
}

function getChat(id, userId) {
  return db
    .prepare(
      "SELECT * FROM chats WHERE id=? AND (user1=? OR user2=?)"
    )
    .get(id, userId, userId);
}

/* Регистрация */
app.post("/api/register", authLimit, (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Логин: 3–20 символов, только буквы, цифры и _"
    });
  }

  if (password.length < 6 || password.length > 100) {
    return res.status(400).json({
      error: "Пароль должен быть от 6 до 100 символов"
    });
  }

  if (db.prepare("SELECT id FROM users WHERE username=?").get(username)) {
    return res.status(409).json({
      error: "Пользователь уже существует"
    });
  }

  const result = db
    .prepare(
      "INSERT INTO users(username,password,created_at) VALUES(?,?,?)"
    )
    .run(
      username,
      bcrypt.hashSync(password, 10),
      Date.now()
    );

  const user = {
    id: Number(result.lastInsertRowid),
    username
  };

  res.json({
    token: makeToken(user.id),
    user
  });
});

/* Вход */
app.post("/api/login", authLimit, (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db
    .prepare("SELECT * FROM users WHERE username=?")
    .get(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({
      error: "Неверный логин или пароль"
    });
  }

  res.json({
    token: makeToken(user.id),
    user: {
      id: user.id,
      username: user.username
    }
  });
});

/* Текущий пользователь */
app.get("/api/me", auth, (req, res) => {
  const user = db
    .prepare("SELECT id,username FROM users WHERE id=?")
    .get(req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "Пользователь не найден"
    });
  }

  res.json(user);
});

/* Поиск пользователей */
app.get("/api/users", auth, (req, res) => {
  const q = String(req.query.q || "").trim();

  if (!q) return res.json([]);

  const users = db
    .prepare(
      `SELECT id,username
       FROM users
       WHERE username LIKE ? AND id<>?
       ORDER BY username
       LIMIT 20`
    )
    .all("%" + q + "%", req.user.id);

  res.json(users);
});

/* Список чатов */
app.get("/api/chats", auth, (req, res) => {
  const chats = db
    .prepare(
      `SELECT
        c.id,
        c.created_at,
        u.id AS user_id,
        u.username,
        (
          SELECT text
          FROM messages m
          WHERE m.chat_id=c.id
          ORDER BY m.id DESC
          LIMIT 1
        ) AS last_text,
        (
          SELECT created_at
          FROM messages m
          WHERE m.chat_id=c.id
          ORDER BY m.id DESC
          LIMIT 1
        ) AS last_time
      FROM chats c
      JOIN users u
        ON u.id=CASE
          WHEN c.user1=? THEN c.user2
          ELSE c.user1
        END
      WHERE c.user1=? OR c.user2=?
      ORDER BY COALESCE(last_time,c.created_at) DESC`
    )
    .all(req.user.id, req.user.id, req.user.id);

  res.json(chats);
});

/* Создать чат */
app.post("/api/chats", auth, (req, res) => {
  const other = Number(req.body.userId);

  const user = db
    .prepare("SELECT id,username FROM users WHERE id=?")
    .get(other);

  if (!user || other === req.user.id) {
    return res.status(400).json({
      error: "Неверный пользователь"
    });
  }

  const a = Math.min(req.user.id, other);
  const b = Math.max(req.user.id, other);

  let chat = db
    .prepare("SELECT * FROM chats WHERE user1=? AND user2=?")
    .get(a, b);

  if (!chat) {
    const result = db
      .prepare(
        "INSERT INTO chats(user1,user2,created_at) VALUES(?,?,?)"
      )
      .run(a, b, Date.now());

    chat = {
      id: Number(result.lastInsertRowid)
    };
  }

  res.json({
    id: chat.id,
    user
  });
});

/* Сообщения */
app.get("/api/chats/:id/messages", auth, (req, res) => {
  const id = Number(req.params.id);

  if (!getChat(id, req.user.id)) {
    return res.status(404).json({
      error: "Чат не найден"
    });
  }

  const messages = db
    .prepare(
      `SELECT
        m.id,
        m.text,
        m.created_at,
        m.sender_id,
        u.username
       FROM messages m
       JOIN users u ON u.id=m.sender_id
       WHERE m.chat_id=?
       ORDER BY m.id ASC
       LIMIT 200`
    )
    .all(id);

  res.json(messages);
});

/* ================= UI ================= */

const page = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M-Talk</title>

<style>
*{box-sizing:border-box}

body{
  margin:0;
  font-family:Arial,sans-serif;
  background:#e9eef5;
  color:#17212b
}

button,input{
  font:inherit
}

button{
  cursor:pointer;
  border:0;
  border-radius:10px;
  padding:10px 14px;
  background:#2aabee;
  color:white
}

.hidden{
  display:none!important
}

.auth{
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:20px
}

.card{
  width:min(400px,100%);
  background:white;
  border-radius:18px;
  padding:25px;
  box-shadow:0 8px 30px #0002
}

.card h1{
  margin-top:0
}

.card input{
  width:100%;
  padding:12px;
  margin:6px 0;
  border:1px solid #ccd5df;
  border-radius:10px
}

.error{
  color:#d33;
  min-height:20px;
  margin-top:8px
}

.switch{
  margin-top:15px;
  text-align:center;
  color:#64748b
}

.switch a{
  color:#168acd;
  cursor:pointer
}

.app{
  height:100vh;
  display:flex
}

.sidebar{
  width:320px;
  background:white;
  border-right:1px solid #ddd;
  display:flex;
  flex-direction:column
}

.top{
  padding:16px;
  border-bottom:1px solid #eee;
  font-weight:bold;
  font-size:20px
}

.search{
  padding:10px;
  position:relative
}

.search input{
  width:100%;
  padding:11px;
  border:1px solid #ddd;
  border-radius:10px
}

.list{
  overflow:auto;
  flex:1
}

.chatitem{
  padding:13px 16px;
  border-bottom:1px solid #f0f0f0;
  cursor:pointer
}

.chatitem:hover,
.chatitem.active{
  background:#eef7ff
}

.name{
  font-weight:bold
}

.last{
  font-size:13px;
  color:#718096;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
  margin-top:4px
}

.main{
  flex:1;
  display:flex;
  flex-direction:column;
  min-width:0
}

.head{
  background:white;
  padding:14px 18px;
  border-bottom:1px solid #ddd;
  font-weight:bold
}

.messages{
  flex:1;
  overflow:auto;
  padding:18px;
  display:flex;
  flex-direction:column;
  gap:7px
}

.msg{
  max-width:min(70%,500px);
  padding:9px 12px;
  border-radius:14px;
  background:white;
  align-self:flex-start;
  word-break:break-word
}

.msg.mine{
  background:#cfeeff;
  align-self:flex-end
}

.time{
  font-size:10px;
  color:#718096;
  margin-top:3px;
  text-align:right
}

.send{
  display:flex;
  gap:8px;
  background:white;
  padding:10px
}

.send input{
  flex:1;
  padding:12px;
  border:1px solid #ddd;
  border-radius:12px
}

.empty{
  margin:auto;
  color:#718096;
  text-align:center
}

.results{
  position:absolute;
  left:10px;
  right:10px;
  top:58px;
  background:white;
  border:1px solid #ddd;
  border-radius:10px;
  z-index:3
}

.result{
  padding:10px;
  cursor:pointer
}

.result:hover{
  background:#eee
}

.back{
  display:none;
  margin-right:8px;
  background:#eee;
  color:#222;
  padding:5px 9px
}

@media(max-width:700px){

  .sidebar{
    width:100%
  }

  .main{
    display:none
  }

  .app.chat-open .sidebar{
    display:none
  }

  .app.chat-open .main{
    display:flex
  }

  .back{
    display:inline-block
  }

  .msg{
    max-width:85%
  }
}
</style>
</head>

<body>

<div id="auth" class="auth">
  <div class="card">

    <h1>💬 M-Talk</h1>

    <div id="authTitle">Вход</div>

    <input
      id="login"
      placeholder="Логин"
      autocomplete="username"
    >

    <input
      id="pass"
      type="password"
      placeholder="Пароль"
      autocomplete="current-password"
    >

    <button
      id="authBtn"
      style="width:100%;margin-top:8px"
    >
      Войти
    </button>

    <div id="authErr" class="error"></div>

    <div class="switch">
      <span id="switchText">Нет аккаунта?</span>
      <a id="switch">Регистрация</a>
    </div>

  </div>
</div>

<div id="app" class="app hidden">

  <aside class="sidebar">

    <div class="top">
      💬 M-Talk
    </div>

    <div class="search">

      <input
        id="search"
        placeholder="Найти пользователя"
      >

      <div id="results" class="results hidden"></div>

    </div>

    <div id="chats" class="list"></div>

  </aside>

  <main class="main">

    <div class="head">
      <button class="back" id="back">←</button>
      <span id="chatTitle">Выберите чат</span>
    </div>

    <div id="messages" class="messages">
      <div class="empty">
        Выберите пользователя слева
      </div>
    </div>

    <div class="send">

      <input
        id="message"
        placeholder="Сообщение..."
        disabled
      >

      <button id="send" disabled>
        ➤
      </button>

    </div>

  </main>

</div>

<script src="/socket.io/socket.io.js"></script>

<script>
const $ = id => document.getElementById(id);

let isReg = false;
let token = localStorage.getItem("mtoken");
let me = null;
let current = null;
let socket = null;

function esc(s){
  return String(s).replace(
    /[&<>"']/g,
    c => ({
      "&":"&amp;",
      "<":"&lt;",
      ">":"&gt;",
      '"':"&quot;",
      "'":"&#39;"
    }[c])
  );
}

async function api(url,opt={}){
  opt.headers = Object.assign(
    {"Content-Type":"application/json"},
    opt.headers || {}
  );

  if(token){
    opt.headers.Authorization = "Bearer " + token;
  }

  const r = await fetch(url,opt);

  const d = await r.json().catch(
    () => ({error:"Ошибка сервера"})
  );

  if(!r.ok){
    throw Error(d.error || "Ошибка");
  }

  return d;
}

$("switch").onclick = () => {

  isReg = !isReg;

  $("authTitle").textContent =
    isReg ? "Регистрация" : "Вход";

  $("authBtn").textContent =
    isReg ? "Создать аккаунт" : "Войти";

  $("switch").textContent =
    isReg ? "Вход" : "Регистрация";

  $("switchText").textContent =
    isReg ? "Уже есть аккаунт?" : "Нет аккаунта?";

  $("authErr").textContent = "";
};

$("authBtn").onclick = async () => {

  try{

    const username = $("login").value.trim();
    const password = $("pass").value;

    const d = await api(
      isReg ? "/api/register" : "/api/login",
      {
        method:"POST",
        body:JSON.stringify({
          username,
          password
        })
      }
    );

    token = d.token;

    localStorage.setItem("mtoken",token);

    start();

  }catch(e){

    $("authErr").textContent = e.message;

  }
};

$("pass").onkeydown = e => {
  if(e.key === "Enter"){
    $("authBtn").click();
  }
};

async function start(){

  try{

    me = await api("/api/me");

    $("auth").classList.add("hidden");
    $("app").classList.remove("hidden");

    socket = io({
      auth:{token}
    });

    socket.on("message",m => {

      if(current && m.chat_id === current.id){
        addMsg(m);
      }

      loadChats();

    });

    await loadChats();

  }catch(e){

    localStorage.removeItem("mtoken");
    token = null;

  }
}

async function loadChats(){

  const rows = await api("/api/chats");

  $("chats").innerHTML =
    rows.length
      ? rows.map(c =>
        '<div class="chatitem ' +
        (current && current.id === c.id ? "active" : "") +
        '" data-id="' + c.id + '">' +

        '<div class="name">' +
        esc(c.username) +
        "</div>" +

        '<div class="last">' +
        esc(c.last_text || "Нет сообщений") +
        "</div>" +

        "</div>"
      ).join("")
      : '<div class="empty">Чатов пока нет</div>';

  document
    .querySelectorAll(".chatitem")
    .forEach(x => {
      x.onclick = () =>
        openChat(Number(x.dataset.id));
    });
}

async function openChat(id){

  try{

    const rows = await api("/api/chats");

    const c = rows.find(x => x.id === id);

    if(!c) return;

    current = {
      id:c.id,
      username:c.username,
      user_id:c.user_id
    };

    $("chatTitle").textContent = c.username;

    $("message").disabled = false;
    $("send").disabled = false;

    $("messages").innerHTML = "";

    const msgs =
      await api("/api/chats/" + id + "/messages");

    msgs.forEach(addMsg);

    if(socket){
      socket.emit("joinChat",id);
    }

    $("app").classList.add("chat-open");

    loadChats();

  }catch(e){

    alert(e.message);

  }
}

function addMsg(m){

  const d = document.createElement("div");

  d.className =
    "msg " +
    (m.sender_id === me.id ? "mine" : "");

  d.innerHTML =
    esc(m.text) +
    '<div class="time">' +
    new Date(m.created_at)
      .toLocaleTimeString([],{
        hour:"2-digit",
        minute:"2-digit"
      }) +
    "</div>";

  $("messages").appendChild(d);

  $("messages").scrollTop =
    $("messages").scrollHeight;
}

function send(){

  const text = $("message").value.trim();

  if(!text || !current || !socket) return;

  socket.emit(
    "sendMessage",
    {
      chatId:current.id,
      text
    },
    r => {

      if(r && r.error){
        alert(r.error);
      }else{
        $("message").value = "";
      }

    }
  );
}

$("send").onclick = send;

$("message").onkeydown = e => {

  if(e.key === "Enter"){
    send();
  }

};

$("back").onclick = () => {

  $("app").classList.remove("chat-open");

  current = null;

  $("message").disabled = true;
  $("send").disabled = true;
};

let timer;

$("search").oninput = () => {

  clearTimeout(timer);

  timer = setTimeout(async () => {

    const q = $("search").value.trim();

    if(!q){
      $("results").classList.add("hidden");
      return;
    }

    const rows =
      await api(
        "/api/users?q=" +
        encodeURIComponent(q)
      );

    $("results").innerHTML =
      rows.map(u =>
        '<div class="result" data-user="' +
        u.id +
        '">👤 ' +
        esc(u.username) +
        "</div>"
      ).join("") ||
      '<div class="result">Ничего не найдено</div>';

    $("results").classList.remove("hidden");

    document
      .querySelectorAll(".result[data-user]")
      .forEach(x => {

        x.onclick = async () => {

          try{

            const c = await api(
              "/api/chats",
              {
                method:"POST",
                body:JSON.stringify({
                  userId:Number(x.dataset.user)
                })
              }
            );

            $("search").value = "";

            $("results")
              .classList
              .add("hidden");

            await loadChats();

            openChat(c.id);

          }catch(e){

            alert(e.message);

          }

        };

      });

  },250);
};

document.onclick = e => {

  if(!e.target.closest(".search")){
    $("results").classList.add("hidden");
  }

};

if(token){
  start();
}
</script>

</body>
</html>`;

app.get("/", (req,res) => {
  res.type("html").send(page);
});

/* Socket.IO */

io.use((socket,next) => {

  try{

    const t =
      socket.handshake.auth &&
      socket.handshake.auth.token;

    socket.user =
      jwt.verify(t,JWT_SECRET);

    next();

  }catch{

    next(new Error("Unauthorized"));

  }

});

io.on("connection", socket => {

  socket.on("joinChat", chatId => {

    if(
      getChat(
        Number(chatId),
        socket.user.id
      )
    ){
      socket.join("chat:" + Number(chatId));
    }

  });

  socket.on("sendMessage",(data,cb) => {

    try{

      const chatId = Number(data.chatId);
      const text = String(data.text || "").trim();

      if(!text || text.length > 2000){
        return cb &&
          cb({
            error:"Сообщение пустое или слишком длинное"
          });
      }

      if(!getChat(chatId,socket.user.id)){
        return cb &&
          cb({
            error:"Нет доступа к чату"
          });
      }

      const time = Date.now();

      const result = db
        .prepare(
          `INSERT INTO messages
           (chat_id,sender_id,text,created_at)
           VALUES(?,?,?,?)`
        )
        .run(
          chatId,
          socket.user.id,
          text,
          time
        );

      const message = {
        id:Number(result.lastInsertRowid),
        chat_id:chatId,
        sender_id:socket.user.id,
        text,
        created_at:time
      };

      io
        .to("chat:" + chatId)
        .emit("message",message);

      if(cb){
        cb({ok:true});
      }

    }catch{

      if(cb){
        cb({
          error:"Ошибка отправки"
        });
      }

    }

  });

});

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "M-Talk running on port " + PORT
    );
  }
);
