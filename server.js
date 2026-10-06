const express = require("express");
const http = require("http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const app = express();
app.set("trust proxy", 1);

const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is not set");
  process.exit(1);
}

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not set");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/register", authLimiter);
app.use("/api/login", authLimiter);

async function db(query, params = []) {
  const result = await pool.query(query, params);
  return result;
}

async function initDb() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (chat_id, user_id)
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await db(`
    CREATE INDEX IF NOT EXISTS idx_chat_members_user
    ON chat_members(user_id)
  `);

  await db(`
    CREATE INDEX IF NOT EXISTS idx_messages_chat
    ON messages(chat_id, id)
  `);

  console.log("PostgreSQL database ready");
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Необходима авторизация"
    });
  }

  try {
    const token = header.slice(7);
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Недействительный токен"
    });
  }
}

async function isMember(chatId, userId) {
  const result = await db(
    `
    SELECT 1
    FROM chat_members
    WHERE chat_id = $1 AND user_id = $2
    LIMIT 1
    `,
    [chatId, userId]
  );

  return result.rowCount > 0;
}

function cleanText(value) {
  return String(value || "").trim().slice(0, 2000);
}

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Логин: 3–20 символов, только буквы, цифры и _"
      });
    }

    if (password.length < 4 || password.length > 100) {
      return res.status(400).json({
        error: "Пароль должен быть от 4 до 100 символов"
      });
    }

    const exists = await db(
      "SELECT id FROM users WHERE LOWER(username) = LOWER($1)",
      [username]
    );

    if (exists.rowCount) {
      return res.status(409).json({
        error: "Такой пользователь уже существует"
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await db(
      `
      INSERT INTO users(username, password_hash)
      VALUES($1, $2)
      RETURNING id, username
      `,
      [username, hash]
    );

    const user = result.rows[0];

    res.json({
      token: makeToken(user),
      user
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const result = await db(
      `
      SELECT id, username, password_hash
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
      `,
      [username]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Неверный логин или пароль"
      });
    }

    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.status(401).json({
        error: "Неверный логин или пароль"
      });
    }

    res.json({
      token: makeToken(user),
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT id, username, created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Пользователь не найден"
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* =========================
   SEARCH USERS
========================= */

app.get("/api/users", auth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();

    if (!q) {
      return res.json([]);
    }

    const result = await db(
      `
      SELECT id, username
      FROM users
      WHERE id <> $1
        AND username ILIKE $2
      ORDER BY username
      LIMIT 20
      `,
      [req.user.id, `%${q}%`]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* =========================
   CREATE / GET PERSONAL CHAT
========================= */

app.post("/api/chats", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const otherUserId = Number(req.body.userId);

    if (!Number.isInteger(otherUserId)) {
      return res.status(400).json({
        error: "Неверный пользователь"
      });
    }

    if (otherUserId === req.user.id) {
      return res.status(400).json({
        error: "Нельзя создать чат с самим собой"
      });
    }

    const other = await client.query(
      "SELECT id, username FROM users WHERE id = $1",
      [otherUserId]
    );

    if (!other.rowCount) {
      return res.status(404).json({
        error: "Пользователь не найден"
      });
    }

    const existing = await client.query(
      `
      SELECT c.id
      FROM chats c
      JOIN chat_members a ON a.chat_id = c.id
      JOIN chat_members b ON b.chat_id = c.id
      WHERE a.user_id = $1
        AND b.user_id = $2
      LIMIT 1
      `,
      [req.user.id, otherUserId]
    );

    if (existing.rowCount) {
      return res.json({
        id: existing.rows[0].id,
        user: other.rows[0]
      });
    }

    await client.query("BEGIN");

    const chat = await client.query(
      "INSERT INTO chats DEFAULT VALUES RETURNING id"
    );

    const chatId = chat.rows[0].id;

    await client.query(
      `
      INSERT INTO chat_members(chat_id, user_id)
      VALUES($1, $2), ($1, $3)
      `,
      [chatId, req.user.id, otherUserId]
    );

    await client.query("COMMIT");

    res.json({
      id: chatId,
      user: other.rows[0]
    });
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(error);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  } finally {
    client.release();
  }
});

/* =========================
   CHAT LIST
========================= */

app.get("/api/chats", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT
        c.id,
        u.id AS user_id,
        u.username,
        lm.text AS last_message,
        lm.created_at AS last_message_at
      FROM chats c

      JOIN chat_members me
        ON me.chat_id = c.id
       AND me.user_id = $1

      JOIN chat_members other
        ON other.chat_id = c.id
       AND other.user_id <> $1

      JOIN users u
        ON u.id = other.user_id

      LEFT JOIN LATERAL (
        SELECT text, created_at
        FROM messages
        WHERE chat_id = c.id
        ORDER BY id DESC
        LIMIT 1
      ) lm ON true

      ORDER BY COALESCE(lm.created_at, c.created_at) DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* =========================
   MESSAGE HISTORY
========================= */

app.get("/api/chats/:id/messages", auth, async (req, res) => {
  try {
    const chatId = Number(req.params.id);

    if (!Number.isInteger(chatId)) {
      return res.status(400).json({
        error: "Неверный чат"
      });
    }

    if (!(await isMember(chatId, req.user.id))) {
      return res.status(403).json({
        error: "Нет доступа"
      });
    }

    const result = await db(
      `
      SELECT
        m.id,
        m.chat_id,
        m.sender_id,
        u.username AS sender_username,
        m.text,
        m.created_at
      FROM messages m
      JOIN users u ON u.id = m.sender_id
      WHERE m.chat_id = $1
      ORDER BY m.id ASC
      LIMIT 200
      `,
      [chatId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* =========================
   SOCKET.IO
========================= */

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("Нет токена"));
    }

    socket.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    next(new Error("Недействительный токен"));
  }
});

io.on("connection", (socket) => {
  socket.on("joinChat", async (chatId) => {
    try {
      chatId = Number(chatId);

      if (!Number.isInteger(chatId)) return;

      if (!(await isMember(chatId, socket.user.id))) {
        return;
      }

      socket.join(`chat:${chatId}`);
    } catch (error) {
      console.error(error);
    }
  });

  socket.on("sendMessage", async (data, callback) => {
    try {
      const chatId = Number(data?.chatId);
      const text = cleanText(data?.text);

      if (!Number.isInteger(chatId)) {
        return callback?.({
          ok: false,
          error: "Неверный чат"
        });
      }

      if (!text) {
        return callback?.({
          ok: false,
          error: "Сообщение пустое"
        });
      }

      if (!(await isMember(chatId, socket.user.id))) {
        return callback?.({
          ok: false,
          error: "Нет доступа"
        });
      }

      const result = await db(
        `
        INSERT INTO messages(chat_id, sender_id, text)
        VALUES($1, $2, $3)
        RETURNING id, chat_id, sender_id, text, created_at
        `,
        [chatId, socket.user.id, text]
      );

      const message = {
        ...result.rows[0],
        sender_username: socket.user.username
      };

      io.to(`chat:${chatId}`).emit("newMessage", message);

      callback?.({
        ok: true
      });
    } catch (error) {
      console.error(error);

      callback?.({
        ok: false,
        error: "Ошибка отправки"
      });
    }
  });
});

/* =========================
   FRONTEND
========================= */

const html = `
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M-Talk</title>

<style>
* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  width: 100%;
  height: 100%;
  font-family: Arial, sans-serif;
  background: #080b12;
  color: #fff;
}

body {
  overflow: hidden;
}

button,
input {
  font: inherit;
}

button {
  cursor: pointer;
}

.screen {
  width: 100%;
  height: 100%;
}

.hidden {
  display: none !important;
}

/* AUTH */

.auth {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100%;
  padding: 20px;
  background:
    radial-gradient(circle at top, #18264d, transparent 45%),
    #080b12;
}

.auth-card {
  width: min(400px, 100%);
  padding: 28px;
  border: 1px solid #28324b;
  border-radius: 22px;
  background: rgba(16, 21, 34, .95);
  box-shadow: 0 20px 70px rgba(0,0,0,.45);
  animation: appear .35s ease;
}

.logo {
  text-align: center;
  font-size: 34px;
  font-weight: 800;
  margin-bottom: 8px;
}

.subtitle {
  text-align: center;
  color: #8994aa;
  margin-bottom: 24px;
}

.auth input {
  width: 100%;
  padding: 13px 15px;
  margin-bottom: 12px;
  border: 1px solid #303a52;
  border-radius: 13px;
  background: #0c111d;
  color: white;
  outline: none;
}

.auth input:focus,
.search input:focus,
.message-input:focus {
  border-color: #637cff;
}

.primary {
  width: 100%;
  padding: 13px;
  border: 0;
  border-radius: 13px;
  background: #526dff;
  color: white;
  font-weight: 700;
}

.secondary {
  width: 100%;
  padding: 12px;
  margin-top: 10px;
  border: 1px solid #303a52;
  border-radius: 13px;
  background: #121827;
  color: white;
}

.error {
  min-height: 20px;
  margin: 8px 0;
  color: #ff6875;
  font-size: 14px;
  text-align: center;
}

/* APP */

.app {
  display: flex;
  height: 100%;
  background:
    radial-gradient(circle at 30% 20%, rgba(72, 92, 180, .08), transparent 35%),
    #080b12;
}

.sidebar {
  width: 330px;
  min-width: 260px;
  border-right: 1px solid #20283a;
  background: #0c101a;
  display: flex;
  flex-direction: column;
}

.top {
  padding: 18px;
  border-bottom: 1px solid #20283a;
}

.top-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.brand {
  font-size: 24px;
  font-weight: 800;
}

.user-name {
  margin-top: 4px;
  color: #8e99ae;
  font-size: 13px;
}

.logout {
  border: 1px solid #30394d;
  border-radius: 10px;
  padding: 7px 10px;
  background: #131927;
  color: #b8c0d1;
}

.search {
  padding: 12px;
}

.search input {
  width: 100%;
  padding: 11px 13px;
  border: 1px solid #2d374c;
  border-radius: 12px;
  outline: none;
  background: #101624;
  color: white;
}

.results {
  padding: 0 12px;
}

.user-result {
  width: 100%;
  padding: 11px;
  margin-bottom: 6px;
  border: 1px solid #242d40;
  border-radius: 11px;
  background: #111725;
  color: white;
  text-align: left;
}

.chats {
  overflow-y: auto;
  padding: 5px 10px 20px;
}

.chat-item {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 11px;
  margin-bottom: 5px;
  border: 0;
  border-radius: 12px;
  background: transparent;
  color: white;
  text-align: left;
}

.chat-item:hover,
.chat-item.active {
  background: #171e2d;
}

.avatar {
  width: 40px;
  height: 40px;
  min-width: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg,#586cff,#8d59ff);
  font-weight: 800;
}

.chat-name {
  font-weight: 700;
}

.last {
  margin-top: 3px;
  color: #7f899d;
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* CHAT */

.chat {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  position: relative;
}

.chat-header {
  height: 65px;
  min-height: 65px;
  display: flex;
  align-items: center;
  padding: 0 18px;
  border-bottom: 1px solid #20283a;
  background: rgba(12,16,26,.94);
  backdrop-filter: blur(10px);
}

.chat-title {
  font-size: 17px;
  font-weight: 700;
}

.messages {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: 18px 18px 10px;
  background:
    radial-gradient(circle at 20% 30%, rgba(86,108,255,.04), transparent 30%),
    radial-gradient(circle at 80% 70%, rgba(141,89,255,.035), transparent 30%);
}

.empty {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #667187;
  text-align: center;
}

.msg-row {
  display: flex;
  margin: 4px 0;
  animation: msg .16s ease;
}

.msg-row.mine {
  justify-content: flex-end;
}

.msg {
  max-width: min(70%, 430px);
  padding: 7px 10px;
  border-radius: 13px;
  background: #171e2c;
  border: 1px solid #242e43;
  font-size: 14px;
  line-height: 1.3;
  word-break: break-word;
}

.mine .msg {
  background: #3e56cc;
  border-color: #4e68e7;
}

.msg-user {
  color: #aeb8cb;
  font-size: 10px;
  margin-bottom: 2px;
}

.mine .msg-user {
  color: #d7ddff;
}

.time {
  display: block;
  margin-top: 3px;
  text-align: right;
  color: #8290aa;
  font-size: 9px;
}

.mine .time {
  color: #c7d0ff;
}

.composer {
  display: flex;
  gap: 8px;
  padding: 10px 12px;
  border-top: 1px solid #20283a;
  background: #0c101a;
}

.message-input {
  flex: 1;
  min-width: 0;
  padding: 10px 13px;
  border: 1px solid #2d374c;
  border-radius: 13px;
  background: #111725;
  color: white;
  outline: none;
}

.send {
  width: 44px;
  border: 0;
  border-radius: 13px;
  background: #526dff;
  color: white;
  font-size: 18px;
}

/* MOBILE */

@media (max-width: 700px) {
  .sidebar {
    width: 100%;
    min-width: 0;
  }

  .chat {
    display: none;
  }

  .app.chat-open .sidebar {
    display: none;
  }

  .app.chat-open .chat {
    display: flex;
  }

  .msg {
    max-width: 78%;
  }

  .back {
    display: block !important;
    margin-right: 10px;
    border: 0;
    background: transparent;
    color: white;
    font-size: 20px;
  }
}

.back {
  display: none;
}

@keyframes appear {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes msg {
  from {
    opacity: 0;
    transform: translateY(4px) scale(.98);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}
</style>
</head>

<body>

<div id="auth" class="screen auth">
  <div class="auth-card">

    <div class="logo">M-Talk</div>
    <div class="subtitle">Интернет-мессенджер</div>

    <input id="username" placeholder="Логин">
    <input id="password" type="password" placeholder="Пароль">

    <div id="authError" class="error"></div>

    <button class="primary" onclick="login()">
      Войти
    </button>

    <button class="secondary" onclick="register()">
      Создать аккаунт
    </button>

  </div>
</div>

<div id="app" class="screen app hidden">

  <aside class="sidebar">

    <div class="top">

      <div class="top-row">
        <div>
          <div class="brand">M-Talk</div>
          <div id="currentUser" class="user-name"></div>
        </div>

        <button class="logout" onclick="logout()">
          Выйти
        </button>
      </div>

    </div>

    <div class="search">
      <input
        id="search"
        placeholder="Поиск пользователей..."
        oninput="searchUsers()"
      >
    </div>

    <div id="results" class="results"></div>

    <div id="chats" class="chats"></div>

  </aside>

  <main class="chat">

    <div class="chat-header">

      <button id="back" class="back" onclick="closeChat()">
        ‹
      </button>

      <div id="chatTitle" class="chat-title">
        Выберите чат
      </div>

    </div>

    <div id="messages" class="messages">

      <div class="empty">
        Выберите пользователя или создайте чат
      </div>

    </div>

    <div class="composer">

      <input
        id="messageInput"
        class="message-input"
        placeholder="Сообщение..."
        autocomplete="off"
        onkeydown="if(event.key==='Enter') sendMessage()"
      >

      <button class="send" onclick="sendMessage()">
        ➤
      </button>

    </div>

  </main>

</div>

<script src="/socket.io/socket.io.js"></script>

<script>
let token = localStorage.getItem("mtalk_token");
let me = null;
let socket = null;
let currentChat = null;
let currentOtherUser = null;

const $ = id => document.getElementById(id);

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = "Bearer " + token;
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Ошибка");
  }

  return data;
}

async function register() {
  $("authError").textContent = "";

  try {
    const data = await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        username: $("username").value,
        password: $("password").value
      })
    });

    token = data.token;
    localStorage.setItem("mtalk_token", token);

    await startApp();
  } catch (error) {
    $("authError").textContent = error.message;
  }
}

async function login() {
  $("authError").textContent = "";

  try {
    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("username").value,
        password: $("password").value
      })
    });

    token = data.token;
    localStorage.setItem("mtalk_token", token);

    await startApp();
  } catch (error) {
    $("authError").textContent = error.message;
  }
}

async function startApp() {
  try {
    me = await api("/api/me");

    $("auth").classList.add("hidden");
    $("app").classList.remove("hidden");

    $("currentUser").textContent = "@" + me.username;

    connectSocket();
    loadChats();
  } catch {
    logout();
  }
}

function connectSocket() {
  if (socket) {
    socket.disconnect();
  }

  socket = io({
    auth: {
      token
    }
  });

  socket.on("connect", () => {
    if (currentChat) {
      socket.emit("joinChat", currentChat);
    }
  });

  socket.on("newMessage", message => {
    if (Number(message.chat_id) !== Number(currentChat)) {
      loadChats();
      return;
    }

    renderMessage(message);
    scrollMessages();
    loadChats();
  });
}

async function searchUsers() {
  const q = $("search").value.trim();
  const box = $("results");

  box.innerHTML = "";

  if (!q) {
    return;
  }

  try {
    const users = await api(
      "/api/users?q=" + encodeURIComponent(q)
    );

    for (const user of users) {
      const button = document.createElement("button");
      button.className = "user-result";
      button.textContent = "@" + user.username;

      button.onclick = () => openUser(user);

      box.appendChild(button);
    }
  } catch {}
}

async function openUser(user) {
  try {
    const chat = await api("/api/chats", {
      method: "POST",
      body: JSON.stringify({
        userId: user.id
      })
    });

    $("results").innerHTML = "";
    $("search").value = "";

    await openChat(chat.id, chat.user);

    loadChats();
  } catch (error) {
    alert(error.message);
  }
}

async function loadChats() {
  try {
    const chats = await api("/api/chats");

    const box = $("chats");
    box.innerHTML = "";

    for (const chat of chats) {
      const button = document.createElement("button");
      button.className = "chat-item";

      const avatar = document.createElement("div");
      avatar.className = "avatar";
      avatar.textContent = chat.username[0].toUpperCase();

      const info = document.createElement("div");
      info.style.minWidth = "0";

      const name = document.createElement("div");
      name.className = "chat-name";
      name.textContent = "@" + chat.username;

      const last = document.createElement("div");
      last.className = "last";
      last.textContent = chat.last_message || "Нет сообщений";

      info.appendChild(name);
      info.appendChild(last);

      button.appendChild(avatar);
      button.appendChild(info);

      button.onclick = () => {
        openChat(chat.id, {
          id: chat.user_id,
          username: chat.username
        });
      };

      box.appendChild(button);
    }
  } catch {}
}

async function openChat(chatId, user) {
  currentChat = chatId;
  currentOtherUser = user;

  $("chatTitle").textContent = "@" + user.username;
  $("app").classList.add("chat-open");

  if (socket) {
    socket.emit("joinChat", chatId);
  }

  const messages = $("messages");
  messages.innerHTML = "";

  try {
    const data = await api(
      "/api/chats/" + chatId + "/messages"
    );

    for (const message of data) {
      renderMessage(message);
    }

    scrollMessages();
  } catch (error) {
    messages.innerHTML =
      '<div class="empty">' +
      escapeHtml(error.message) +
      "</div>";
  }
}

function closeChat() {
  $("app").classList.remove("chat-open");
}

function renderMessage(message) {
  const box = $("messages");

  const empty = box.querySelector(".empty");
  if (empty) {
    empty.remove();
  }

  const mine =
    Number(message.sender_id) === Number(me.id);

  const row = document.createElement("div");
  row.className = "msg-row" + (mine ? " mine" : "");

  const msg = document.createElement("div");
  msg.className = "msg";

  const username = document.createElement("div");
  username.className = "msg-user";
  username.textContent =
    mine ? "Вы" : "@" + message.sender_username;

  const text = document.createElement("div");
  text.textContent = message.text;

  const time = document.createElement("span");
  time.className = "time";

  const date = new Date(message.created_at);

  time.textContent =
    date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit"
    });

  msg.appendChild(username);
  msg.appendChild(text);
  msg.appendChild(time);

  row.appendChild(msg);
  box.appendChild(row);
}

function scrollMessages() {
  const box = $("messages");

  requestAnimationFrame(() => {
    box.scrollTop = box.scrollHeight;
  });
}

function sendMessage() {
  const input = $("messageInput");
  const text = input.value.trim();

  if (!text || !currentChat || !socket) {
    return;
  }

  socket.emit(
    "sendMessage",
    {
      chatId: currentChat,
      text
    },
    result => {
      if (!result?.ok) {
        alert(result?.error || "Ошибка отправки");
        return;
      }

      input.value = "";
      input.focus();
    }
  );
}

function logout() {
  token = null;
  me = null;
  currentChat = null;
  currentOtherUser = null;

  localStorage.removeItem("mtalk_token");

  if (socket) {
    socket.disconnect();
    socket = null;
  }

  $("app").classList.add("hidden");
  $("auth").classList.remove("hidden");

  $("username").value = "";
  $("password").value = "";
  $("authError").textContent = "";
}

if (token) {
  startApp();
}
</script>

</body>
</html>
`;

app.get("/", (req, res) => {
  res.send(html);
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "M-Talk"
  });
});

/* =========================
   START
========================= */

async function start() {
  try {
    await initDb();

    server.listen(PORT, "0.0.0.0", () => {
      console.log("M-Talk running on port " + PORT);
    });
  } catch (error) {
    console.error("Database startup error:", error);
    process.exit(1);
  }
}

start();
