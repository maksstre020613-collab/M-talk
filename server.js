const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");

if (process.env.NODE_ENV === "production" && !process.env.JWT_SECRET) {
  console.warn("WARNING: set JWT_SECRET in production.");
}

/* =========================
   DATABASE
========================= */

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

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

  FOREIGN KEY(user1)
    REFERENCES users(id)
    ON DELETE CASCADE,

  FOREIGN KEY(user2)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL,
  sender_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,

  FOREIGN KEY(conversation_id)
    REFERENCES conversations(id)
    ON DELETE CASCADE,

  FOREIGN KEY(sender_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_conv
ON messages(conversation_id,id);

CREATE INDEX IF NOT EXISTS idx_users_username
ON users(username);
`);

/* =========================
   SECURITY
========================= */

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],

        scriptSrc: ["'self'"],

        styleSrc: ["'self'"],

        connectSrc: [
          "'self'",
          "ws:",
          "wss:"
        ],

        imgSrc: [
          "'self'",
          "data:"
        ],

        fontSrc: ["'self'"],

        objectSrc: ["'none'"],

        baseUri: ["'self'"],

        frameAncestors: ["'none'"]
      }
    }
  })
);

app.use(
  express.json({
    limit: "32kb"
  })
);

/* =========================
   RATE LIMIT
========================= */

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/", apiLimiter);

/* =========================
   AUTH
========================= */

function tokenFor(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Требуется вход"
    });
  }

  try {
    req.user = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: "Сессия истекла"
    });
  }
}

/* =========================
   DATABASE HELPERS
========================= */

function normalizePair(a, b) {
  return a < b ? [a, b] : [b, a];
}

function getConversation(a, b) {
  const [u1, u2] = normalizePair(a, b);

  return db
    .prepare(
      `
      SELECT *
      FROM conversations
      WHERE user1=? AND user2=?
      `
    )
    .get(u1, u2);
}

function createConversation(a, b) {
  const [u1, u2] = normalizePair(a, b);

  const existing = getConversation(a, b);

  if (existing) {
    return existing;
  }

  try {
    const result = db
      .prepare(
        `
        INSERT INTO conversations
        (user1,user2,created_at)
        VALUES(?,?,?)
        `
      )
      .run(
        u1,
        u2,
        Date.now()
      );

    return db
      .prepare(
        `
        SELECT *
        FROM conversations
        WHERE id=?
        `
      )
      .get(result.lastInsertRowid);
  } catch {
    return getConversation(a, b);
  }
}

function userById(id) {
  return db
    .prepare(
      `
      SELECT id,username,created_at
      FROM users
      WHERE id=?
      `
    )
    .get(id);
}

function member(conversation, userId) {
  return (
    conversation &&
    (
      conversation.user1 === userId ||
      conversation.user2 === userId
    )
  );
}

/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  authLimiter,
  async (req, res) => {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    if (
      !/^[A-Za-z0-9_А-Яа-яЁё-]{3,20}$/.test(
        username
      )
    ) {
      return res.status(400).json({
        error:
          "Ник: 3–20 символов; буквы, цифры, _ или -"
      });
    }

    if (
      password.length < 6 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error:
          "Пароль должен быть от 6 до 128 символов"
      });
    }

    const exists = db
      .prepare(
        "SELECT id FROM users WHERE username=?"
      )
      .get(username);

    if (exists) {
      return res.status(409).json({
        error: "Такой ник уже занят"
      });
    }

    try {

      const passwordHash =
        await bcrypt.hash(password, 12);

      const result = db
        .prepare(
          `
          INSERT INTO users
          (username,password_hash,created_at)
          VALUES(?,?,?)
          `
        )
        .run(
          username,
          passwordHash,
          Date.now()
        );

      const user =
        userById(result.lastInsertRowid);

      return res.status(201).json({
        token: tokenFor(user),
        user
      });

    } catch (error) {

      if (
        String(error.message)
          .includes("UNIQUE")
      ) {
        return res.status(409).json({
          error: "Такой ник уже занят"
        });
      }

      console.error(
        "Register error:",
        error
      );

      return res.status(500).json({
        error:
          "Не удалось создать аккаунт"
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  authLimiter,
  async (req, res) => {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    const user = db
      .prepare(
        "SELECT * FROM users WHERE username=?"
      )
      .get(username);

    if (
      !user ||
      !(await bcrypt.compare(
        password,
        user.password_hash
      ))
    ) {
      return res.status(401).json({
        error:
          "Неверный ник или пароль"
      });
    }

    return res.json({
      token: tokenFor(user),
      user: userById(user.id)
    });
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  auth,
  (req, res) => {

    const user =
      userById(req.user.sub);

    if (!user) {
      return res.status(401).json({
        error:
          "Пользователь не найден"
      });
    }

    res.json({
      user
    });
  }
);

/* =========================
   USER SEARCH
========================= */

app.get(
  "/api/users",
  auth,
  (req, res) => {

    const q =
      String(req.query.q || "").trim();

    if (!q) {
      return res.json([]);
    }

    const safe =
      q.replace(/[\\%_]/g, "\\$&");

    const users =
      db.prepare(
        `
        SELECT id,username
        FROM users
        WHERE username LIKE ?
        ESCAPE '\\'
        AND id<>?
        ORDER BY username
        LIMIT 20
        `
      ).all(
        "%" + safe + "%",
        req.user.sub
      );

    res.json(users);
  }
);

/* =========================
   CHAT LIST
========================= */

app.get(
  "/api/chats",
  auth,
  (req, res) => {

    const rows =
      db.prepare(
        `
        SELECT
          c.id,
          c.user1,
          c.user2,

          CASE
            WHEN c.user1=?
            THEN u2.username
            ELSE u1.username
          END AS username,

          (
            SELECT body
            FROM messages m
            WHERE m.conversation_id=c.id
            ORDER BY m.id DESC
            LIMIT 1
          ) AS last_message,

          (
            SELECT created_at
            FROM messages m
            WHERE m.conversation_id=c.id
            ORDER BY m.id DESC
            LIMIT 1
          ) AS last_time

        FROM conversations c

        JOIN users u1
          ON u1.id=c.user1

        JOIN users u2
          ON u2.id=c.user2

        WHERE c.user1=?
           OR c.user2=?

        ORDER BY
          COALESCE(
            last_time,
            c.created_at
          ) DESC
        `
      ).all(
        req.user.sub,
        req.user.sub,
        req.user.sub
      );

    res.json(rows);
  }
);

/* =========================
   CREATE CHAT
========================= */

app.post(
  "/api/chats",
  auth,
  (req, res) => {

    const other =
      Number(req.body.userId);

    if (
      !Number.isInteger(other) ||
      other === req.user.sub
    ) {
      return res.status(400).json({
        error:
          "Неверный пользователь"
      });
    }

    const user =
      userById(other);

    if (!user) {
      return res.status(404).json({
        error:
          "Пользователь не найден"
      });
    }

    const conversation =
      createConversation(
        req.user.sub,
        other
      );

    res.json({
      id: conversation.id,
      user
    });
  }
);

/* =========================
   MESSAGES
========================= */

app.get(
  "/api/chats/:id/messages",
  auth,
  (req, res) => {

    const chatId =
      Number(req.params.id);

    if (!Number.isInteger(chatId)) {
      return res.status(400).json({
        error: "Неверный чат"
      });
    }

    const conversation =
      db.prepare(
        "SELECT * FROM conversations WHERE id=?"
      ).get(chatId);

    if (
      !member(
        conversation,
        req.user.sub
      )
    ) {
      return res.status(403).json({
        error: "Нет доступа"
      });
    }

    const messages =
      db.prepare(
        `
        SELECT
          m.id,
          m.body,
          m.created_at,
          m.sender_id,
          u.username

        FROM messages m

        JOIN users u
          ON u.id=m.sender_id

        WHERE m.conversation_id=?

        ORDER BY m.id DESC

        LIMIT 100
        `
      )
      .all(conversation.id)
      .reverse();

    res.json(messages);
  }
);

/* =========================
   FRONTEND
========================= */

const INDEX_HTML = `<!doctype html>
<html lang="ru">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>M-Talk</title>

<link
  rel="stylesheet"
  href="/style.css"
>

</head>

<body>

<div id="auth" class="auth">

<div class="authbox">

<div class="logo">
M<span>-</span>Talk
</div>

<div class="muted">
Безопасный интернет-мессенджер
</div>

<div class="tabs">

<button
  id="lt"
  class="active"
>
Войти
</button>

<button id="rt">
Регистрация
</button>

</div>

<input
  id="un"
  placeholder="Ник"
  maxlength="20"
  autocomplete="username"
>

<input
  id="pw"
  type="password"
  placeholder="Пароль"
  maxlength="128"
  autocomplete="current-password"
>

<button id="ab">
Войти
</button>

<div id="err"></div>

</div>

</div>


<div id="app" class="hidden">

<header>

<div class="brand">
M<span>-</span>Talk
</div>

<div
  class="me"
  id="me"
></div>

</header>


<div class="layout">

<aside>

<div class="search">

<input
  id="search"
  placeholder="🔎  Поиск"
>

</div>

<div id="results"></div>

<div class="section">
Чаты
</div>

<div id="chats"></div>

</aside>


<section class="chat">

<div
  id="empty"
  class="empty"
>

<div>💬</div>

<b>
Выберите чат
</b>

<span>
Найдите пользователя через поиск
</span>

</div>


<div
  id="chatbox"
  class="hidden"
>

<div class="chathead">

<div
  class="avatar"
  id="avatar"
>
M
</div>

<div>

<b id="ctitle"></b>

<small id="cstatus">
был(а) недавно
</small>

</div>

</div>


<div id="msgs"></div>


<form id="form">

<input
  id="body"
  autocomplete="off"
  maxlength="4000"
  placeholder="Сообщение"
>

<button type="submit">
➤
</button>

</form>

</div>

</section>

</div>

</div>


<script
  src="/socket.io/socket.io.js"
></script>

<script
  src="/app.js"
></script>

</body>

</html>`;


/* =========================
   CSS
========================= */

const STYLE_CSS = `

*{
box-sizing:border-box
}

body{
margin:0;
font-family:
Arial,
system-ui,
sans-serif;
background:#d9e5ef;
color:#17212b
}

button,
input{
font:inherit
}

.hidden{
display:none!important
}

.auth{
min-height:100vh;
display:grid;
place-items:center;
background:
linear-gradient(
135deg,
#d9e5ef,
#eef5f9
)
}

.authbox{
width:min(390px,92%);
background:#fff;
padding:30px;
border-radius:18px;
box-shadow:
0 12px 45px #0002
}

.logo{
font-size:40px;
font-weight:800;
text-align:center
}

.logo span,
.brand span{
color:#3390ec
}

.muted{
color:#8493a2;
text-align:center;
margin:
4px 0 24px
}

.tabs{
display:flex;
background:#edf2f6;
border-radius:10px;
padding:3px;
margin-bottom:14px
}

.tabs button{
width:50%;
border:0;
background:transparent;
padding:10px;
border-radius:8px;
color:#71808e
}

.tabs .active{
background:#fff;
color:#2387df;
box-shadow:
0 1px 5px #0001
}

.authbox input{
display:block;
width:100%;
padding:13px;
margin:9px 0;
border:
1px solid #d5dfe8;
border-radius:10px;
outline:none
}

.authbox>#ab{
width:100%;
border:0;
padding:13px;
border-radius:10px;
background:#3390ec;
color:#fff;
font-weight:bold;
margin-top:5px
}

.authbox #err{
text-align:center;
color:#e04f5f;
min-height:22px;
margin-top:10px
}

#app{
height:100vh;
background:#fff
}

header{
height:56px;
background:#fff;
border-bottom:
1px solid #dfe6ec;
display:flex;
align-items:center;
justify-content:space-between;
padding:0 18px
}

.brand{
font-weight:800;
font-size:24px
}

.me{
color:#657483
}

.layout{
height:
calc(100vh - 56px);
display:flex;
max-width:1200px;
margin:auto
}

aside{
width:350px;
border-right:
1px solid #dfe6ec;
overflow:auto;
background:#fff
}

.search{
padding:10px
}

.search input{
width:100%;
padding:
10px 13px;
border:0;
background:#f1f3f5;
border-radius:10px;
outline:0
}

.section{
font-size:12px;
text-transform:uppercase;
color:#8a98a5;
padding:
12px 15px 7px
}

.person,
.chatrow{
display:flex;
align-items:center;
gap:11px;
padding:
10px 14px;
cursor:pointer
}

.person:hover,
.chatrow:hover{
background:#f1f3f5
}

.chatrow.active{
background:#e7f2fd
}

.avatar{
width:45px;
height:45px;
border-radius:50%;
background:#55a7e8;
color:#fff;
display:grid;
place-items:center;
font-weight:bold;
flex:none
}

.chatrow .txt{
min-width:0
}

.chatrow b{
display:block
}

.chatrow small{
display:block;
color:#7b8995;
white-space:nowrap;
overflow:hidden;
text-overflow:ellipsis;
margin-top:3px
}

.chat{
flex:1;
min-width:0;
background:#e6ebef;
position:relative
}

.empty{
height:100%;
display:flex;
flex-direction:column;
align-items:center;
justify-content:center;
color:#6d7b87;
gap:8px
}

.empty div{
font-size:55px
}

.chathead{
height:60px;
background:#fff;
display:flex;
align-items:center;
gap:10px;
padding:
7px 15px;
border-bottom:
1px solid #dce3e8
}

.chathead .avatar{
width:42px;
height:42px
}

.chathead small{
display:block;
color:#87939e;
font-size:12px;
margin-top:2px
}

.chathead b{
font-size:15px
}

#msgs{
height:
calc(100% - 112px);
overflow:auto;
padding:18px;
display:flex;
flex-direction:column;
gap:4px
}

.bubble{
max-width:70%;
padding:
7px 10px;
border-radius:10px;
background:#fff;
box-shadow:
0 1px 1px #0001;
align-self:flex-start
}

.bubble.mine{
background:#e1ffc7;
align-self:flex-end
}

.bubble p{
margin:0;
white-space:pre-wrap;
overflow-wrap:anywhere
}

.bubble small{
font-size:10px;
color:#7c898f;
float:right;
margin:
5px 0 0 9px
}

form{
height:52px;
background:#fff;
display:flex;
gap:8px;
padding:7px;
border-top:
1px solid #d9e1e7
}

form input{
flex:1;
border:0;
background:#f0f2f4;
border-radius:10px;
padding:
10px 13px;
outline:0
}

form button{
border:0;
background:#3390ec;
color:white;
border-radius:10px;
width:46px;
font-size:20px
}

@media(max-width:700px){

aside{
width:100%
}

.chat{
display:none
}

.layout.chatopen aside{
display:none
}

.layout.chatopen .chat{
display:block
}

.me{
font-size:12px
}

}

`;


/* =========================
   FRONTEND JS
========================= */

const APP_JS = `

let token =
localStorage.getItem("mtalk_token");

let me = null;

let socket = null;

let current = null;

let chats = [];


const $ =
x => document.getElementById(x);


function esc(value){

return String(value)
.replace(
/[&<>"']/g,
char => ({
"&":"&amp;",
"<":"&lt;",
">":"&gt;",
"\\\"":"&quot;",
"'":"&#039;"
}[char])
);

}


/* =========================
   API
========================= */

async function api(
url,
options={}
){

options.headers = {
...(options.headers || {}),

Authorization:
"Bearer " + token,

"Content-Type":
"application/json"
};

const response =
await fetch(
url,
options
);

const data =
await response
.json()
.catch(
() => ({})
);

if(!response.ok){

throw new Error(
data.error ||
"Ошибка запроса"
);

}

return data;

}


/* =========================
   AUTH MODE
========================= */

let mode = "login";


$("lt").onclick =
() => setMode("login");

$("rt").onclick =
() => setMode("register");


function setMode(newMode){

mode = newMode;

$("lt")
.classList
.toggle(
"active",
mode === "login"
);

$("rt")
.classList
.toggle(
"active",
mode === "register"
);

$("ab").textContent =
mode === "login"
? "Войти"
: "Создать аккаунт";

$("pw").autocomplete =
mode === "login"
? "current-password"
: "new-password";

$("err").textContent = "";

}


/* =========================
   LOGIN / REGISTER
========================= */

$("ab").onclick =
async () => {

try{

const endpoint =
mode === "login"
? "/api/login"
: "/api/register";

const response =
await fetch(
endpoint,
{
method:"POST",

headers:{
"Content-Type":
"application/json"
},

body:JSON.stringify({
username:
$("un").value.trim(),

password:
$("pw").value
})
}
);

const data =
await response
.json()
.catch(
() => ({})
);

if(!response.ok){

throw new Error(
data.error ||
"Ошибка запроса"
);

}

token =
data.token;

localStorage.setItem(
"mtalk_token",
token
);

await boot();

}catch(error){

$("err").textContent =
error.message ||
"Ошибка сети";

}

};


/* =========================
   START APP
========================= */

async function boot(){

if(!token){
return;
}

try{

const data =
await api("/api/me");

me =
data.user;

$("me").textContent =
"👤 " + me.username;

$("auth")
.classList
.add("hidden");

$("app")
.classList
.remove("hidden");


socket =
io({
auth:{
token
}
});


socket.on(
"message",
message => {

if(
current &&
message.conversation_id ===
current.id
){

addMsg(message);

}

loadChats();

}
);


await loadChats();

}catch{

localStorage.removeItem(
"mtalk_token"
);

token = null;

}

}


/* =========================
   LOAD CHATS
========================= */

async function loadChats(){

chats =
await api("/api/chats");

$("chats").innerHTML =
chats.map(
chat => ` +
"`" + `<div class="chatrow ${
current &&
current.id === chat.id
? "active"
: ""
}"
onclick="openChat(${chat.id})">

<div class="avatar">
${esc(
chat.username[0]
.toUpperCase()
)}
</div>

<div class="txt">

<b>
${esc(chat.username)}
</b>

<small>
${esc(
chat.last_message ||
"Новый чат"
)}
</small>

</div>

</div>` + "`" + `
`
).join("");

}


/* =========================
   OPEN CHAT
========================= */

window.openChat =
async id => {

const chat =
chats.find(
item => item.id === id
);

if(!chat){
return;
}

current = {
id:chat.id,
username:chat.username
};

$("empty")
.classList
.add("hidden");

$("chatbox")
.classList
.remove("hidden");

$("ctitle").textContent =
chat.username;

$("avatar").textContent =
chat.username[0]
.toUpperCase();

$("msgs").innerHTML = "";

socket.emit(
"joinChat",
id
);

const messages =
await api(
"/api/chats/" +
id +
"/messages"
);

messages.forEach(addMsg);

scrollMessages();

await loadChats();

};


/* =========================
   MESSAGE
========================= */

function addMsg(message){

const element =
document.createElement("div");

element.className =
"bubble " +
(
message.sender_id === me.id
? "mine"
: ""
);

element.innerHTML = ` +
"`" + `
<p>
${esc(message.body)}
</p>

<small>
${new Date(
message.created_at
).toLocaleTimeString(
[],
{
hour:"2-digit",
minute:"2-digit"
}
)}
</small>
` + "`" + `;

$("msgs")
.appendChild(
element
);

scrollMessages();

}


function scrollMessages(){

$("msgs").scrollTop =
$("msgs").scrollHeight;

}


/* =========================
   SEND MESSAGE
========================= */

$("form").onsubmit =
event => {

event.preventDefault();

const body =
$("body")
.value
.trim();

if(
body &&
current &&
socket &&
socket.connected
){

socket.emit(
"sendMessage",
{
chatId:
current.id,

body
}
);

$("body").value = "";

}

};


/* =========================
   SEARCH
========================= */

let searchTimer;

$("search").oninput =
() => {

clearTimeout(
searchTimer
);

searchTimer =
setTimeout(
searchUsers,
250
);

};


async function searchUsers(){

const query =
$("search")
.value
.trim();

if(!query){

$("results")
.innerHTML = "";

return;

}

try{

const users =
await api(
"/api/users?q=" +
encodeURIComponent(query)
);

$("results").innerHTML =
users.map(
user => ` +
"`" + `
<div
class="person"
onclick="startChat(${user.id})"
>

<div class="avatar">
${esc(
user.username[0]
.toUpperCase()
)}
</div>

<b>
${esc(user.username)}
</b>

</div>
` + "`" + `
`
).join("");

}catch{

$("results").innerHTML = "";

}

}


/* =========================
   START CHAT
========================= */

window.startChat =
async userId => {

const chat =
await api(
"/api/chats",
{
method:"POST",

body:JSON.stringify({
userId
})
}
);

$("search").value = "";

$("results").innerHTML = "";

await loadChats();

openChat(chat.id);

};


/* =========================
   START
========================= */

if(token){

boot();

}

`;


/* =========================
   ROUTES
========================= */

app.get(
  "/",
  (req, res) => {
    res.type("html").send(INDEX_HTML);
  }
);

app.get(
  "/style.css",
  (req, res) => {
    res.type("css").send(STYLE_CSS);
  }
);

app.get(
  "/app.js",
  (req, res) => {
    res
      .type("application/javascript")
      .send(APP_JS);
  }
);


/* =========================
   SOCKET.IO AUTH
========================= */

io.use(
  (socket, next) => {

    try {

      const token =
        socket.handshake.auth?.token ||
        "";

      socket.user =
        jwt.verify(
          token,
          JWT_SECRET
        );

      next();

    } catch {

      next(
        new Error(
          "AUTH_FAILED"
        )
      );

    }

  }
);


/* =========================
   ONLINE USERS
========================= */

const online =
  new Map();


/* =========================
   SOCKET CONNECTION
========================= */

io.on(
  "connection",
  socket => {

    const userId =
      Number(socket.user.sub);

    if(!online.has(userId)){

      online.set(
        userId,
        new Set()
      );

    }

    online
      .get(userId)
      .add(socket.id);

    io.emit(
      "presence",
      {
        userId,
        online:true
      }
    );


    /* JOIN CHAT */

    socket.on(
      "joinChat",
      chatId => {

        const conversation =
          db
          .prepare(
            `
            SELECT *
            FROM conversations
            WHERE id=?
            `
          )
          .get(
            Number(chatId)
          );

        if(
          member(
            conversation,
            userId
          )
        ){

          socket.join(
            "chat:" +
            conversation.id
          );

        }

      }
    );


    /* SEND MESSAGE */

    socket.on(
      "sendMessage",
      payload => {

        const chatId =
          Number(
            payload?.chatId
          );

        const body =
          String(
            payload?.body || ""
          ).trim();

        if(
          !body ||
          body.length > 4000
        ){

          return;

        }

        const conversation =
          db
          .prepare(
            `
            SELECT *
            FROM conversations
            WHERE id=?
            `
          )
          .get(chatId);

        if(
          !member(
            conversation,
            userId
          )
        ){

          return;

        }

        const result =
          db
          .prepare(
            `
            INSERT INTO messages
            (
              conversation_id,
              sender_id,
              body,
              created_at
            )
            VALUES(?,?,?,?)
            `
          )
          .run(
            chatId,
            userId,
            body,
            Date.now()
          );


        const message =
          db
          .prepare(
            `
            SELECT
              m.id,
              m.body,
              m.created_at,
              m.sender_id,
              m.conversation_id,
              u.username

            FROM messages m

            JOIN users u
              ON u.id=m.sender_id

            WHERE m.id=?
            `
          )
          .get(
            result.lastInsertRowid
          );


        io
          .to("chat:" + chatId)
          .emit(
            "message",
            message
          );

      }
    );


    /* DISCONNECT */

    socket.on(
      "disconnect",
      () => {

        const users =
          online.get(userId);

        if(!users){
          return;
        }

        users.delete(
          socket.id
        );

        if(users.size === 0){

          online.delete(
            userId
          );

          io.emit(
            "presence",
            {
              userId,
              online:false
            }
          );

        }

      }
    );

  }
);


/* =========================
   START SERVER
========================= */

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "M-Talk running on port " +
      PORT
    );

  }
);
