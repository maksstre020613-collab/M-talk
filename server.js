const express = require("express");
const http = require("http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "mtalk-development-secret";

if (!process.env.JWT_SECRET) {
  console.warn("WARNING: JWT_SECRET is not set.");
}

/* ================= DATABASE ================= */

fs.mkdirSync(path.join(__dirname, "data"), {
  recursive: true
});

const db = new Database(
  path.join(__dirname, "data", "mtalk.db")
);

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

/* ================= SECURITY ================= */

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],

        // ВАЖНО: разрешаем встроенный JS
        scriptSrc: [
          "'self'",
          "'unsafe-inline'"
        ],

        // Разрешаем встроенный CSS
        styleSrc: [
          "'self'",
          "'unsafe-inline'"
        ],

        connectSrc: [
          "'self'",
          "ws:",
          "wss:"
        ],

        imgSrc: [
          "'self'",
          "data:"
        ],

        objectSrc: [
          "'none'"
        ],

        baseUri: [
          "'self'"
        ],

        frameAncestors: [
          "'none'"
        ]
      }
    }
  })
);

app.use(
  express.json({
    limit: "32kb"
  })
);

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

/* ================= AUTH ================= */

function createToken(id) {
  return jwt.sign(
    { id },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Не авторизован"
    });
  }

  try {
    req.user = jwt.verify(
      header.substring(7),
      JWT_SECRET
    );

    next();
  } catch {
    res.status(401).json({
      error: "Сессия истекла"
    });
  }
}

function getChat(chatId, userId) {
  return db.prepare(`
    SELECT *
    FROM chats
    WHERE id = ?
      AND (user1 = ? OR user2 = ?)
  `).get(
    chatId,
    userId,
    userId
  );
}

/* ================= REGISTER ================= */

app.post(
  "/api/register",
  authLimit,
  (req, res) => {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    if (
      !/^[a-zA-Z0-9_]{3,20}$/.test(username)
    ) {
      return res.status(400).json({
        error:
          "Логин: 3–20 символов, только буквы, цифры и _"
      });
    }

    if (
      password.length < 6 ||
      password.length > 100
    ) {
      return res.status(400).json({
        error:
          "Пароль должен быть от 6 до 100 символов"
      });
    }

    const exists = db
      .prepare(
        "SELECT id FROM users WHERE username = ?"
      )
      .get(username);

    if (exists) {
      return res.status(409).json({
        error: "Такой пользователь уже существует"
      });
    }

    const hash =
      bcrypt.hashSync(password, 10);

    const result = db.prepare(`
      INSERT INTO users
      (username, password, created_at)
      VALUES (?, ?, ?)
    `).run(
      username,
      hash,
      Date.now()
    );

    const user = {
      id: Number(result.lastInsertRowid),
      username
    };

    res.json({
      token: createToken(user.id),
      user
    });
  }
);

/* ================= LOGIN ================= */

app.post(
  "/api/login",
  authLimit,
  (req, res) => {

    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    const user = db
      .prepare(
        "SELECT * FROM users WHERE username = ?"
      )
      .get(username);

    if (
      !user ||
      !bcrypt.compareSync(
        password,
        user.password
      )
    ) {
      return res.status(401).json({
        error: "Неверный логин или пароль"
      });
    }

    res.json({
      token: createToken(user.id),
      user: {
        id: user.id,
        username: user.username
      }
    });
  }
);

/* ================= ME ================= */

app.get("/api/me", auth, (req, res) => {

  const user = db
    .prepare(`
      SELECT id, username
      FROM users
      WHERE id = ?
    `)
    .get(req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "Пользователь не найден"
    });
  }

  res.json(user);
});

/* ================= SEARCH ================= */

app.get("/api/users", auth, (req, res) => {

  const q =
    String(req.query.q || "").trim();

  if (!q) {
    return res.json([]);
  }

  const users = db
    .prepare(`
      SELECT id, username
      FROM users
      WHERE username LIKE ?
        AND id != ?
      ORDER BY username
      LIMIT 20
    `)
    .all(
      "%" + q + "%",
      req.user.id
    );

  res.json(users);
});

/* ================= CHATS ================= */

app.get("/api/chats", auth, (req, res) => {

  const chats = db
    .prepare(`
      SELECT
        c.id,
        c.created_at,
        u.id AS user_id,
        u.username,

        (
          SELECT text
          FROM messages m
          WHERE m.chat_id = c.id
          ORDER BY m.id DESC
          LIMIT 1
        ) AS last_text,

        (
          SELECT created_at
          FROM messages m
          WHERE m.chat_id = c.id
          ORDER BY m.id DESC
          LIMIT 1
        ) AS last_time

      FROM chats c

      JOIN users u
      ON u.id =
        CASE
          WHEN c.user1 = ?
          THEN c.user2
          ELSE c.user1
        END

      WHERE c.user1 = ?
         OR c.user2 = ?

      ORDER BY
        COALESCE(last_time, c.created_at) DESC
    `)
    .all(
      req.user.id,
      req.user.id,
      req.user.id
    );

  res.json(chats);
});

/* ================= CREATE CHAT ================= */

app.post("/api/chats", auth, (req, res) => {

  const otherId =
    Number(req.body.userId);

  if (
    !Number.isInteger(otherId) ||
    otherId === req.user.id
  ) {
    return res.status(400).json({
      error: "Неверный пользователь"
    });
  }

  const other = db
    .prepare(`
      SELECT id, username
      FROM users
      WHERE id = ?
    `)
    .get(otherId);

  if (!other) {
    return res.status(404).json({
      error: "Пользователь не найден"
    });
  }

  const user1 =
    Math.min(req.user.id, otherId);

  const user2 =
    Math.max(req.user.id, otherId);

  let chat = db
    .prepare(`
      SELECT *
      FROM chats
      WHERE user1 = ?
        AND user2 = ?
    `)
    .get(
      user1,
      user2
    );

  if (!chat) {

    const result = db.prepare(`
      INSERT INTO chats
      (user1, user2, created_at)
      VALUES (?, ?, ?)
    `).run(
      user1,
      user2,
      Date.now()
    );

    chat = {
      id: Number(result.lastInsertRowid)
    };
  }

  res.json({
    id: chat.id,
    user: other
  });
});

/* ================= MESSAGES ================= */

app.get(
  "/api/chats/:id/messages",
  auth,
  (req, res) => {

    const chatId =
      Number(req.params.id);

    if (
      !getChat(
        chatId,
        req.user.id
      )
    ) {
      return res.status(404).json({
        error: "Чат не найден"
      });
    }

    const messages = db
      .prepare(`
        SELECT
          m.id,
          m.chat_id,
          m.sender_id,
          m.text,
          m.created_at,
          u.username

        FROM messages m

        JOIN users u
        ON u.id = m.sender_id

        WHERE m.chat_id = ?

        ORDER BY m.id ASC

        LIMIT 200
      `)
      .all(chatId);

    res.json(messages);
  }
);

/* ================= FRONTEND ================= */

const HTML = `<!DOCTYPE html>
<html lang="ru">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>M-Talk</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Arial, sans-serif;
  background: #e9eef5;
  color: #17212b;
}

button,
input {
  font: inherit;
}

button {
  border: 0;
  border-radius: 10px;
  cursor: pointer;
}

.hidden {
  display: none !important;
}

/* AUTH */

.auth {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.card {
  width: min(400px, 100%);
  background: white;
  padding: 25px;
  border-radius: 20px;
  box-shadow: 0 10px 40px #0002;
}

.card h1 {
  margin-top: 0;
}

.card input {
  display: block;
  width: 100%;
  padding: 13px;
  margin: 8px 0;
  border: 1px solid #ccd5df;
  border-radius: 10px;
  outline: none;
}

.card input:focus {
  border-color: #2aabee;
}

.mainButton {
  width: 100%;
  padding: 13px;
  margin-top: 8px;
  background: #2aabee;
  color: white;
}

.error {
  min-height: 22px;
  margin-top: 8px;
  color: #e53935;
}

.switch {
  text-align: center;
  margin-top: 15px;
  color: #718096;
}

.switch a {
  color: #168acd;
  cursor: pointer;
}

/* APP */

.app {
  height: 100vh;
  display: flex;
}

.sidebar {
  width: 320px;
  background: white;
  border-right: 1px solid #ddd;
  display: flex;
  flex-direction: column;
}

.logo {
  padding: 16px;
  font-size: 21px;
  font-weight: bold;
  border-bottom: 1px solid #eee;
}

.search {
  position: relative;
  padding: 10px;
}

.search input {
  width: 100%;
  padding: 11px;
  border: 1px solid #ddd;
  border-radius: 10px;
  outline: none;
}

.results {
  position: absolute;
  z-index: 10;
  left: 10px;
  right: 10px;
  top: 60px;
  background: white;
  border: 1px solid #ddd;
  border-radius: 10px;
  overflow: hidden;
}

.result {
  padding: 12px;
  cursor: pointer;
}

.result:hover {
  background: #eef7ff;
}

.chats {
  flex: 1;
  overflow-y: auto;
}

.chat {
  padding: 13px 16px;
  border-bottom: 1px solid #f0f0f0;
  cursor: pointer;
}

.chat:hover,
.chat.active {
  background: #eef7ff;
}

.username {
  font-weight: bold;
}

.preview {
  color: #718096;
  font-size: 13px;
  margin-top: 4px;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}

/* CHAT */

.main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.header {
  background: white;
  padding: 14px 18px;
  border-bottom: 1px solid #ddd;
  font-weight: bold;
}

.back {
  display: none;
  margin-right: 8px;
  padding: 6px 10px;
  background: #eee;
}

.messages {
  flex: 1;
  overflow-y: auto;
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.empty {
  margin: auto;
  text-align: center;
  color: #718096;
}

.message {
  max-width: 70%;
  padding: 9px 12px;
  background: white;
  border-radius: 14px;
  align-self: flex-start;
  word-break: break-word;
}

.message.mine {
  background: #cfeeff;
  align-self: flex-end;
}

.time {
  margin-top: 3px;
  font-size: 10px;
  color: #718096;
  text-align: right;
}

.send {
  display: flex;
  gap: 8px;
  padding: 10px;
  background: white;
}

.send input {
  flex: 1;
  min-width: 0;
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 12px;
  outline: none;
}

.send button {
  width: 50px;
  background: #2aabee;
  color: white;
}

@media(max-width:700px) {

  .sidebar {
    width: 100%;
  }

  .main {
    display: none;
  }

  .app.chat-open .sidebar {
    display: none;
  }

  .app.chat-open .main {
    display: flex;
  }

  .back {
    display: inline-block;
  }

  .message {
    max-width: 85%;
  }
}

</style>

</head>

<body>

<!-- AUTH -->

<div id="auth" class="auth">

  <div class="card">

    <h1>💬 M-Talk</h1>

    <div id="authTitle">
      Вход
    </div>

    <input
      id="username"
      placeholder="Логин"
      autocomplete="username"
    >

    <input
      id="password"
      type="password"
      placeholder="Пароль"
      autocomplete="current-password"
    >

    <button
      id="authButton"
      class="mainButton"
    >
      Войти
    </button>

    <div id="authError" class="error"></div>

    <div class="switch">

      <span id="switchText">
        Нет аккаунта?
      </span>

      <a id="switchButton">
        Регистрация
      </a>

    </div>

  </div>

</div>

<!-- APP -->

<div id="app" class="app hidden">

  <aside class="sidebar">

    <div class="logo">
      💬 M-Talk
    </div>

    <div class="search">

      <input
        id="search"
        placeholder="Найти пользователя..."
      >

      <div
        id="results"
        class="results hidden"
      ></div>

    </div>

    <div
      id="chats"
      class="chats"
    ></div>

  </aside>

  <main class="main">

    <div class="header">

      <button
        id="back"
        class="back"
      >
        ←
      </button>

      <span id="chatName">
        Выберите чат
      </span>

    </div>

    <div
      id="messages"
      class="messages"
    >

      <div class="empty">
        Выберите чат
      </div>

    </div>

    <div class="send">

      <input
        id="messageInput"
        placeholder="Сообщение..."
        disabled
      >

      <button
        id="sendButton"
        disabled
      >
        ➤
      </button>

    </div>

  </main>

</div>

<script src="/socket.io/socket.io.js"></script>

<script>

let token =
  localStorage.getItem("mtalk_token");

let me = null;
let socket = null;
let currentChat = null;
let registration = false;

const $ = id =>
  document.getElementById(id);

/* ESCAPE */

function escapeHTML(value) {

  return String(value).replace(
    /[&<>"']/g,
    function(char) {

      const map = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      };

      return map[char];
    }
  );
}

/* API */

async function api(url, options) {

  options = options || {};

  options.headers =
    Object.assign(
      {
        "Content-Type":
          "application/json"
      },
      options.headers || {}
    );

  if (token) {
    options.headers.Authorization =
      "Bearer " + token;
  }

  const response =
    await fetch(url, options);

  const data =
    await response
      .json()
      .catch(function() {
        return {
          error: "Ошибка сервера"
        };
      });

  if (!response.ok) {
    throw new Error(
      data.error || "Ошибка"
    );
  }

  return data;
}

/* AUTH MODE */

$("switchButton").onclick =
function() {

  registration =
    !registration;

  $("authTitle").textContent =
    registration
      ? "Регистрация"
      : "Вход";

  $("authButton").textContent =
    registration
      ? "Создать аккаунт"
      : "Войти";

  $("switchButton").textContent =
    registration
      ? "Войти"
      : "Регистрация";

  $("switchText").textContent =
    registration
      ? "Уже есть аккаунт?"
      : "Нет аккаунта?";

  $("authError").textContent =
    "";
};

/* LOGIN / REGISTER */

$("authButton").onclick =
async function() {

  $("authError").textContent =
    "Подождите...";

  try {

    const username =
      $("username").value.trim();

    const password =
      $("password").value;

    const result =
      await api(
        registration
          ? "/api/register"
          : "/api/login",
        {
          method: "POST",

          body: JSON.stringify({
            username,
            password
          })
        }
      );

    token = result.token;

    localStorage.setItem(
      "mtalk_token",
      token
    );

    $("authError").textContent =
      "";

    await startApp();

  } catch(error) {

    $("authError").textContent =
      error.message;

  }
};

$("password").onkeydown =
function(event) {

  if (event.key === "Enter") {
    $("authButton").click();
  }

};

/* START */

async function startApp() {

  try {

    me =
      await api("/api/me");

    $("auth")
      .classList
      .add("hidden");

    $("app")
      .classList
      .remove("hidden");

    socket =
      io({
        auth: {
          token: token
        }
      });

    socket.on(
      "connect_error",
      function() {
        console.log(
          "Socket connection error"
        );
      }
    );

    socket.on(
      "message",
      function(message) {

        if (
          currentChat &&
          message.chat_id ===
            currentChat.id
        ) {
          addMessage(message);
        }

        loadChats();
      }
    );

    await loadChats();

  } catch(error) {

    localStorage.removeItem(
      "mtalk_token"
    );

    token = null;

  }
}

/* CHATS */

async function loadChats() {

  const chats =
    await api("/api/chats");

  if (!chats.length) {

    $("chats").innerHTML =
      '<div class="empty">Нет чатов</div>';

    return;
  }

  $("chats").innerHTML =
    chats
      .map(function(chat) {

        const active =
          currentChat &&
          currentChat.id === chat.id
            ? "active"
            : "";

        return (
          '<div class="chat ' +
          active +
          '" data-id="' +
          chat.id +
          '">' +

          '<div class="username">' +
          escapeHTML(
            chat.username
          ) +
          "</div>" +

          '<div class="preview">' +
          escapeHTML(
            chat.last_text ||
            "Нет сообщений"
          ) +
          "</div>" +

          "</div>"
        );

      })
      .join("");

  document
    .querySelectorAll(".chat")
    .forEach(function(element) {

      element.onclick =
        function() {

          openChat(
            Number(
              element.dataset.id
            )
          );

        };

    });
}

/* OPEN CHAT */

async function openChat(chatId) {

  const chats =
    await api("/api/chats");

  const chat =
    chats.find(function(item) {
      return item.id === chatId;
    });

  if (!chat) return;

  currentChat = {
    id: chat.id,
    username: chat.username,
    user_id: chat.user_id
  };

  $("chatName").textContent =
    chat.username;

  $("messageInput").disabled =
    false;

  $("sendButton").disabled =
    false;

  $("messages").innerHTML =
    "";

  const messages =
    await api(
      "/api/chats/" +
      chatId +
      "/messages"
    );

  messages.forEach(addMessage);

  if (socket) {

    socket.emit(
      "joinChat",
      chatId
    );

  }

  $("app")
    .classList
    .add("chat-open");

  await loadChats();
}

/* MESSAGE */

function addMessage(message) {

  const element =
    document.createElement("div");

  element.className =
    "message" +
    (
      message.sender_id === me.id
        ? " mine"
        : ""
    );

  element.innerHTML =
    escapeHTML(message.text) +

    '<div class="time">' +

    new Date(
      message.created_at
    ).toLocaleTimeString(
      [],
      {
        hour: "2-digit",
        minute: "2-digit"
      }
    ) +

    "</div>";

  $("messages")
    .appendChild(element);

  $("messages").scrollTop =
    $("messages").scrollHeight;
}

/* SEND */

function sendMessage() {

  const text =
    $("messageInput")
      .value
      .trim();

  if (
    !text ||
    !currentChat ||
    !socket
  ) {
    return;
  }

  socket.emit(
    "sendMessage",
    {
      chatId: currentChat.id,
      text: text
    },
    function(result) {

      if (
        result &&
        result.error
      ) {

        alert(result.error);
        return;

      }

      $("messageInput").value =
        "";

    }
  );
}

$("sendButton").onclick =
sendMessage;

$("messageInput").onkeydown =
function(event) {

  if (event.key === "Enter") {
    sendMessage();
  }

};

/* BACK */

$("back").onclick =
function() {

  $("app")
    .classList
    .remove("chat-open");

  currentChat = null;

  $("messageInput").disabled =
    true;

  $("sendButton").disabled =
    true;

  $("chatName").textContent =
    "Выберите чат";

};

/* SEARCH */

let searchTimer = null;

$("search").oninput =
function() {

  clearTimeout(searchTimer);

  searchTimer =
    setTimeout(
      searchUsers,
      250
    );
};

async function searchUsers() {

  const query =
    $("search").value.trim();

  if (!query) {

    $("results")
      .classList
      .add("hidden");

    return;
  }

  try {

    const users =
      await api(
        "/api/users?q=" +
        encodeURIComponent(query)
      );

    if (!users.length) {

      $("results").innerHTML =
        '<div class="result">' +
        "Ничего не найдено" +
        "</div>";

    } else {

      $("results").innerHTML =
        users
          .map(function(user) {

            return (
              '<div class="result" ' +
              'data-user="' +
              user.id +
              '">' +
              "👤 " +
              escapeHTML(
                user.username
              ) +
              "</div>"
            );

          })
          .join("");

      document
        .querySelectorAll(
          ".result[data-user]"
        )
        .forEach(function(element) {

          element.onclick =
          async function() {

            try {

              const chat =
                await api(
                  "/api/chats",
                  {
                    method: "POST",

                    body:
                      JSON.stringify({
                        userId:
                          Number(
                            element.dataset.user
                          )
                      })
                  }
                );

              $("search").value =
                "";

              $("results")
                .classList
                .add("hidden");

              await loadChats();

              await openChat(
                chat.id
              );

            } catch(error) {

              alert(
                error.message
              );

            }

          };

        });
    }

    $("results")
      .classList
      .remove("hidden");

  } catch(error) {

    console.log(error);

  }
}

document.onclick =
function(event) {

  if (
    !event.target.closest(
      ".search"
    )
  ) {

    $("results")
      .classList
      .add("hidden");

  }

};

/* AUTO LOGIN */

if (token) {
  startApp();
}

</script>

</body>
</html>`;

/* ================= PAGE ================= */

app.get("/", function(req, res) {
  res.type("html").send(HTML);
});

/* ================= SOCKET ================= */

io.use(function(socket, next) {

  try {

    const token =
      socket.handshake.auth &&
      socket.handshake.auth.token;

    socket.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    next();

  } catch(error) {

    next(
      new Error("Unauthorized")
    );

  }
});

io.on(
  "connection",
  function(socket) {

    socket.on(
      "joinChat",
      function(chatId) {

        chatId =
          Number(chatId);

        if (
          getChat(
            chatId,
            socket.user.id
          )
        ) {

          socket.join(
            "chat:" + chatId
          );

        }

      }
    );

    socket.on(
      "sendMessage",
      function(data, callback) {

        try {

          const chatId =
            Number(data.chatId);

          const text =
            String(
              data.text || ""
            ).trim();

          if (
            !text ||
            text.length > 2000
          ) {

            return callback({
              error:
                "Сообщение пустое или слишком длинное"
            });

          }

          if (
            !getChat(
              chatId,
              socket.user.id
            )
          ) {

            return callback({
              error:
                "Нет доступа к этому чату"
            });

          }

          const createdAt =
            Date.now();

          const result =
            db.prepare(`
              INSERT INTO messages
              (
                chat_id,
                sender_id,
                text,
                created_at
              )
              VALUES (?, ?, ?, ?)
            `).run(
              chatId,
              socket.user.id,
              text,
              createdAt
            );

          const message = {
            id:
              Number(
                result.lastInsertRowid
              ),

            chat_id:
              chatId,

            sender_id:
              socket.user.id,

            text:
              text,

            created_at:
              createdAt
          };

          io
            .to("chat:" + chatId)
            .emit(
              "message",
              message
            );

          callback({
            ok: true
          });

        } catch(error) {

          console.error(error);

          callback({
            error:
              "Ошибка отправки сообщения"
          });

        }

      }
    );

  }
);

/* ================= START ================= */

server.listen(
  PORT,
  "0.0.0.0",
  function() {

    console.log(
      "M-Talk running on port " +
      PORT
    );

  }
);
