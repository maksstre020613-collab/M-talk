const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");

// ============================================================
// CONFIG
// ============================================================

const app = express();

app.set("trust proxy", 1);

const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
    process.env.JWT_SECRET ||
    "M-Talk-development-secret-change-this";

const DATA_DIR = path.join(__dirname, "data");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ============================================================
// DATABASE
// ============================================================

const dbPath = path.join(DATA_DIR, "mtalk.db");

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,

    FOREIGN KEY(user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(user2_id) REFERENCES users(id) ON DELETE CASCADE,

    UNIQUE(user1_id, user2_id)
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

CREATE INDEX IF NOT EXISTS idx_messages_chat
ON messages(chat_id, id);

CREATE INDEX IF NOT EXISTS idx_chats_user1
ON chats(user1_id);

CREATE INDEX IF NOT EXISTS idx_chats_user2
ON chats(user2_id);

CREATE INDEX IF NOT EXISTS idx_users_username
ON users(username);
`);

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],

                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                ],

                // ЕДИНСТВЕННОЕ ИСПРАВЛЕНИЕ
                scriptSrcAttr: [
                    "'unsafe-inline'",
                ],

                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                ],

                connectSrc: [
                    "'self'",
                    "ws:",
                    "wss:",
                ],

                imgSrc: [
                    "'self'",
                    "data:",
                ],

                objectSrc: ["'none'"],

                baseUri: ["'self'"],

                frameAncestors: ["'none'"],
            },
        },
    })
);

app.use(express.json({ limit: "32kb" }));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        error: "Слишком много попыток. Попробуйте позже.",
    },
});

// ============================================================
// HELPERS
// ============================================================

function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            username: user.username,
        },
        JWT_SECRET,
        {
            expiresIn: "7d",
        }
    );
}

function authMiddleware(req, res, next) {
    try {
        const header = req.headers.authorization;

        if (!header || !header.startsWith("Bearer ")) {
            return res.status(401).json({
                error: "Необходима авторизация",
            });
        }

        const token = header.substring(7);

        const payload = jwt.verify(token, JWT_SECRET);

        req.user = payload;

        next();
    } catch (error) {
        return res.status(401).json({
            error: "Недействительный или просроченный токен",
        });
    }
}

function normalizeUsername(username) {
    return String(username || "")
        .trim()
        .replace(/\s+/g, "");
}

function getUserById(id) {
    return db
        .prepare(
            `
            SELECT id, username, created_at
            FROM users
            WHERE id = ?
            `
        )
        .get(id);
}

function getChatForUsers(userA, userB) {
    const a = Math.min(userA, userB);
    const b = Math.max(userA, userB);

    return db
        .prepare(
            `
            SELECT *
            FROM chats
            WHERE user1_id = ?
              AND user2_id = ?
            `
        )
        .get(a, b);
}

function userIsInChat(userId, chatId) {
    return db
        .prepare(
            `
            SELECT id
            FROM chats
            WHERE id = ?
              AND (user1_id = ? OR user2_id = ?)
            `
        )
        .get(chatId, userId, userId);
}

// ============================================================
// REGISTER
// ============================================================

app.post(
    "/api/register",
    authLimiter,
    async (req, res) => {
        try {
            let { username, password } = req.body;

            username = normalizeUsername(username);
            password = String(password || "");

            if (username.length < 3 || username.length > 24) {
                return res.status(400).json({
                    error:
                        "Имя пользователя должно содержать от 3 до 24 символов.",
                });
            }

            if (!/^[a-zA-Zа-яА-ЯёЁ0-9_]+$/.test(username)) {
                return res.status(400).json({
                    error:
                        "В имени можно использовать буквы, цифры и _.",
                });
            }

            if (password.length < 6 || password.length > 128) {
                return res.status(400).json({
                    error:
                        "Пароль должен содержать от 6 до 128 символов.",
                });
            }

            const existing = db
                .prepare(
                    `
                    SELECT id
                    FROM users
                    WHERE username = ? COLLATE NOCASE
                    `
                )
                .get(username);

            if (existing) {
                return res.status(409).json({
                    error: "Такой пользователь уже существует.",
                });
            }

            const passwordHash = await bcrypt.hash(
                password,
                10
            );

            const result = db
                .prepare(
                    `
                    INSERT INTO users
                    (username, password_hash, created_at)
                    VALUES (?, ?, ?)
                    `
                )
                .run(
                    username,
                    passwordHash,
                    Date.now()
                );

            const user = getUserById(result.lastInsertRowid);

            const token = createToken(user);

            return res.json({
                ok: true,
                token,
                user,
            });
        } catch (error) {
            console.error("REGISTER ERROR:", error);

            return res.status(500).json({
                error: "Ошибка сервера.",
            });
        }
    }
);

// ============================================================
// LOGIN
// ============================================================

app.post(
    "/api/login",
    authLimiter,
    async (req, res) => {
        try {
            let { username, password } = req.body;

            username = normalizeUsername(username);
            password = String(password || "");

            const user = db
                .prepare(
                    `
                    SELECT *
                    FROM users
                    WHERE username = ? COLLATE NOCASE
                    `
                )
                .get(username);

            if (!user) {
                return res.status(401).json({
                    error: "Неверный логин или пароль.",
                });
            }

            const valid = await bcrypt.compare(
                password,
                user.password_hash
            );

            if (!valid) {
                return res.status(401).json({
                    error: "Неверный логин или пароль.",
                });
            }

            const publicUser = {
                id: user.id,
                username: user.username,
                created_at: user.created_at,
            };

            const token = createToken(publicUser);

            return res.json({
                ok: true,
                token,
                user: publicUser,
            });
        } catch (error) {
            console.error("LOGIN ERROR:", error);

            return res.status(500).json({
                error: "Ошибка сервера.",
            });
        }
    }
);

// ============================================================
// CURRENT USER
// ============================================================

app.get(
    "/api/me",
    authMiddleware,
    (req, res) => {
        const user = getUserById(req.user.id);

        if (!user) {
            return res.status(404).json({
                error: "Пользователь не найден.",
            });
        }

        res.json({
            user,
        });
    }
);

// ============================================================
// SEARCH USERS
// ============================================================

app.get(
    "/api/users",
    authMiddleware,
    (req, res) => {
        try {
            const q = String(req.query.q || "")
                .trim()
                .slice(0, 30);

            if (!q) {
                return res.json({
                    users: [],
                });
            }

            const users = db
                .prepare(
                    `
                    SELECT
                        id,
                        username,
                        created_at
                    FROM users
                    WHERE username LIKE ?
                      AND id != ?
                    ORDER BY username
                    LIMIT 20
                    `
                )
                .all(
                    `%${q}%`,
                    req.user.id
                );

            res.json({
                users,
            });
        } catch (error) {
            console.error("SEARCH ERROR:", error);

            res.status(500).json({
                error: "Ошибка сервера.",
            });
        }
    }
);

// ============================================================
// GET CHATS
// ============================================================

app.get(
    "/api/chats",
    authMiddleware,
    (req, res) => {
        try {
            const chats = db
                .prepare(
                    `
                    SELECT
                        c.id,
                        c.created_at,

                        CASE
                            WHEN c.user1_id = @userId
                            THEN u2.id
                            ELSE u1.id
                        END AS other_id,

                        CASE
                            WHEN c.user1_id = @userId
                            THEN u2.username
                            ELSE u1.username
                        END AS other_username

                    FROM chats c

                    JOIN users u1
                        ON u1.id = c.user1_id

                    JOIN users u2
                        ON u2.id = c.user2_id

                    WHERE
                        c.user1_id = @userId
                        OR
                        c.user2_id = @userId

                    ORDER BY c.id DESC
                    `
                )
                .all({
                    userId: req.user.id,
                });

            res.json({
                chats,
            });
        } catch (error) {
            console.error("GET CHATS ERROR:", error);

            res.status(500).json({
                error: "Ошибка сервера.",
            });
        }
    }
);

// ============================================================
// CREATE / GET CHAT
// ============================================================

app.post(
    "/api/chats",
    authMiddleware,
    (req, res) => {
        try {
            const otherUserId = Number(
                req.body.userId
            );

            if (!Number.isInteger(otherUserId)) {
                return res.status(400).json({
                    error: "Неверный пользователь.",
                });
            }

            if (otherUserId === req.user.id) {
                return res.status(400).json({
                    error:
                        "Нельзя создать чат с самим собой.",
                });
            }

            const otherUser = getUserById(
                otherUserId
            );

            if (!otherUser) {
                return res.status(404).json({
                    error:
                        "Пользователь не найден.",
                });
            }

            let chat = getChatForUsers(
                req.user.id,
                otherUserId
            );

            if (!chat) {
                const user1 = Math.min(
                    req.user.id,
                    otherUserId
                );

                const user2 = Math.max(
                    req.user.id,
                    otherUserId
                );

                const result = db
                    .prepare(
                        `
                        INSERT INTO chats
                        (
                            user1_id,
                            user2_id,
                            created_at
                        )
                        VALUES (?, ?, ?)
                        `
                    )
                    .run(
                        user1,
                        user2,
                        Date.now()
                    );

                chat = db
                    .prepare(
                        `
                        SELECT *
                        FROM chats
                        WHERE id = ?
                        `
                    )
                    .get(
                        result.lastInsertRowid
                    );
            }

            res.json({
                ok: true,
                chat: {
                    id: chat.id,
                    other_id: otherUser.id,
                    other_username:
                        otherUser.username,
                },
            });
        } catch (error) {
            console.error(
                "CREATE CHAT ERROR:",
                error
            );

            res.status(500).json({
                error: "Ошибка сервера.",
            });
        }
    }
);

// ============================================================
// GET MESSAGES
// ============================================================

app.get(
    "/api/chats/:id/messages",
    authMiddleware,
    (req, res) => {
        try {
            const chatId = Number(
                req.params.id
            );

            if (!Number.isInteger(chatId)) {
                return res.status(400).json({
                    error: "Неверный ID чата.",
                });
            }

            if (
                !userIsInChat(
                    req.user.id,
                    chatId
                )
            ) {
                return res.status(403).json({
                    error: "Нет доступа к этому чату.",
                });
            }

            const messages = db
                .prepare(
                    `
                    SELECT
                        m.id,
                        m.chat_id,
                        m.sender_id,
                        m.text,
                        m.created_at,
                        u.username AS sender_username

                    FROM messages m

                    JOIN users u
                        ON u.id = m.sender_id

                    WHERE m.chat_id = ?

                    ORDER BY m.id ASC

                    LIMIT 200
                    `
                )
                .all(chatId);

            res.json({
                messages,
            });
        } catch (error) {
            console.error(
                "GET MESSAGES ERROR:",
                error
            );

            res.status(500).json({
                error: "Ошибка сервера.",
            });
        }
    }
);

// ============================================================
// FRONTEND
// ============================================================

const HTML = `<!DOCTYPE html>
<html lang="ru">

<head>
<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
/>

<title>M-Talk</title>

<style>

* {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    padding: 0;
    width: 100%;
    height: 100%;
}

body {
    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background:
        linear-gradient(
            135deg,
            #10131a,
            #171c27
        );

    color: #fff;
}

button,
input {
    font: inherit;
}

button {
    cursor: pointer;
}

.hidden {
    display: none !important;
}

/* AUTH */

.auth-screen {
    min-height: 100vh;

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 20px;
}

.auth-box {
    width: 100%;
    max-width: 420px;

    padding: 30px;

    border-radius: 22px;

    background:
        rgba(25, 29, 39, 0.95);

    box-shadow:
        0 20px 70px
        rgba(0, 0, 0, .45);
}

.logo {
    text-align: center;

    font-size: 38px;
    font-weight: 800;

    margin-bottom: 8px;
}

.subtitle {
    text-align: center;

    color: #9da6b7;

    margin-bottom: 28px;
}

.input {
    width: 100%;

    padding: 14px 15px;

    margin-bottom: 12px;

    border: 1px solid #333b4d;

    border-radius: 13px;

    outline: none;

    color: white;

    background: #11151d;
}

.input:focus {
    border-color: #5d8cff;
}

.btn {
    width: 100%;

    padding: 14px;

    border: 0;

    border-radius: 13px;

    color: white;

    background: #4f7cff;

    font-weight: 700;

    margin-top: 5px;
}

.btn:hover {
    background: #628bff;
}

.switch {
    text-align: center;

    margin-top: 18px;

    color: #9da6b7;
}

.switch span {
    color: #6d96ff;

    cursor: pointer;
}

.error {
    margin-top: 12px;

    text-align: center;

    color: #ff7373;
}

/* APP */

.app {
    width: 100%;
    height: 100vh;

    display: flex;

    overflow: hidden;
}

.sidebar {
    width: 330px;

    flex-shrink: 0;

    border-right: 1px solid #2b3241;

    background: #11151d;

    display: flex;

    flex-direction: column;
}

.sidebar-head {
    padding: 20px;

    border-bottom: 1px solid #2b3241;
}

.sidebar-title {
    font-size: 25px;

    font-weight: 800;
}

.me {
    color: #8994a9;

    font-size: 13px;

    margin-top: 5px;
}

.search {
    padding: 12px;
}

.chat-list {
    overflow-y: auto;

    flex: 1;
}

.chat {
    padding: 15px 18px;

    border-bottom: 1px solid #202633;

    cursor: pointer;
}

.chat:hover {
    background: #191f2b;
}

.chat.active {
    background: #20293a;
}

.chat-name {
    font-weight: 700;
}

.chat-id {
    color: #7f8aa0;

    font-size: 12px;

    margin-top: 4px;
}

.main {
    flex: 1;

    min-width: 0;

    display: flex;

    flex-direction: column;
}

.chat-head {
    min-height: 72px;

    display: flex;

    align-items: center;

    padding: 15px 20px;

    border-bottom: 1px solid #2b3241;

    background: #151a23;
}

.chat-title {
    font-weight: 800;

    font-size: 18px;
}

.messages {
    flex: 1;

    overflow-y: auto;

    padding: 20px;
}

.message {
    max-width: 75%;

    margin-bottom: 12px;

    padding: 10px 13px;

    border-radius: 15px;

    background: #202735;

    word-wrap: break-word;
}

.message.mine {
    margin-left: auto;

    background: #426bd3;
}

.message-user {
    font-size: 11px;

    opacity: .7;

    margin-bottom: 4px;
}

.message-time {
    font-size: 10px;

    opacity: .55;

    margin-top: 5px;

    text-align: right;
}

.composer {
    display: flex;

    gap: 10px;

    padding: 14px;

    border-top: 1px solid #2b3241;

    background: #151a23;
}

.composer input {
    flex: 1;

    min-width: 0;

    padding: 13px 15px;

    border: 1px solid #343c4c;

    border-radius: 13px;

    background: #10141b;

    color: white;

    outline: none;
}

.send {
    width: 52px;

    border: 0;

    border-radius: 13px;

    background: #4f7cff;

    color: white;

    font-size: 20px;
}

.empty {
    height: 100%;

    display: flex;

    align-items: center;

    justify-content: center;

    color: #788398;

    text-align: center;

    padding: 20px;
}

.logout {
    margin-top: 12px;

    padding: 9px 12px;

    border: 1px solid #343c4c;

    border-radius: 10px;

    background: transparent;

    color: #b6bfce;
}

.logout:hover {
    background: #202632;
}

/* MOBILE */

@media (max-width: 700px) {

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

    .mobile-back {
        display: block !important;
    }
}

.mobile-back {
    display: none;

    margin-right: 12px;

    border: 0;

    background: transparent;

    color: white;

    font-size: 22px;
}

</style>
</head>

<body>

<div id="authScreen" class="auth-screen">

    <div class="auth-box">

        <div class="logo">
            M-Talk
        </div>

        <div class="subtitle">
            Интернет-мессенджер
        </div>

        <div id="loginForm">

            <input
                id="loginUsername"
                class="input"
                placeholder="Имя пользователя"
                autocomplete="username"
            >

            <input
                id="loginPassword"
                class="input"
                type="password"
                placeholder="Пароль"
                autocomplete="current-password"
            >

            <button
                class="btn"
                onclick="login()"
            >
                Войти
            </button>

            <div class="switch">
                Нет аккаунта?
                <span onclick="showRegister()">
                    Регистрация
                </span>
            </div>

        </div>

        <div id="registerForm" class="hidden">

            <input
                id="registerUsername"
                class="input"
                placeholder="Имя пользователя"
                autocomplete="username"
            >

            <input
                id="registerPassword"
                class="input"
                type="password"
                placeholder="Пароль"
                autocomplete="new-password"
            >

            <button
                class="btn"
                onclick="register()"
            >
                Создать аккаунт
            </button>

            <div class="switch">
                Уже есть аккаунт?
                <span onclick="showLogin()">
                    Войти
                </span>
            </div>

        </div>

        <div id="authError" class="error"></div>

    </div>

</div>


<div id="app" class="app hidden">

    <aside class="sidebar">

        <div class="sidebar-head">

            <div class="sidebar-title">
                M-Talk
            </div>

            <div id="me" class="me"></div>

            <button
                class="logout"
                onclick="logout()"
            >
                Выйти
            </button>

        </div>

        <div class="search">

            <input
                id="searchInput"
                class="input"
                placeholder="Найти пользователя..."
                oninput="searchUsers()"
            >

        </div>

        <div
            id="chatList"
            class="chat-list"
        ></div>

    </aside>


    <main class="main">

        <div class="chat-head">

            <button
                class="mobile-back"
                onclick="closeChat()"
            >
                ←
            </button>

            <div
                id="chatTitle"
                class="chat-title"
            >
                Выберите чат
            </div>

        </div>

        <div
            id="messages"
            class="messages"
        >
            <div class="empty">
                Выберите пользователя,
                чтобы начать общение.
            </div>
        </div>

        <div class="composer">

            <input
                id="messageInput"
                placeholder="Введите сообщение..."
                onkeydown="messageKey(event)"
                disabled
            >

            <button
                id="sendButton"
                class="send"
                onclick="sendMessage()"
                disabled
            >
                ➤
            </button>

        </div>

    </main>

</div>


<script src="/socket.io/socket.io.js"></script>

<script>

let token = localStorage.getItem("mtalk_token");
let currentUser = null;
let currentChat = null;
let socket = null;


// ============================================================
// API
// ============================================================

async function api(url, options = {}) {

    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    if (token) {
        headers.Authorization =
            "Bearer " + token;
    }

    const response = await fetch(
        url,
        {
            ...options,
            headers
        }
    );

    let data = {};

    try {
        data = await response.json();
    } catch (e) {}

    if (!response.ok) {
        throw new Error(
            data.error ||
            "Ошибка сервера"
        );
    }

    return data;
}


// ============================================================
// AUTH UI
// ============================================================

function showLogin() {

    document
        .getElementById("loginForm")
        .classList.remove("hidden");

    document
        .getElementById("registerForm")
        .classList.add("hidden");

    clearAuthError();
}

function showRegister() {

    document
        .getElementById("loginForm")
        .classList.add("hidden");

    document
        .getElementById("registerForm")
        .classList.remove("hidden");

    clearAuthError();
}

function showAuthError(text) {

    document
        .getElementById("authError")
        .textContent = text;
}

function clearAuthError() {

    document
        .getElementById("authError")
        .textContent = "";
}


// ============================================================
// REGISTER
// ============================================================

async function register() {

    clearAuthError();

    const username =
        document
            .getElementById(
                "registerUsername"
            )
            .value;

    const password =
        document
            .getElementById(
                "registerPassword"
            )
            .value;

    try {

        const data = await api(
            "/api/register",
            {
                method: "POST",

                body: JSON.stringify({
                    username,
                    password
                })
            }
        );

        token = data.token;

        localStorage.setItem(
            "mtalk_token",
            token
        );

        await startApp();

    } catch (error) {

        showAuthError(
            error.message
        );
    }
}


// ============================================================
// LOGIN
// ============================================================

async function login() {

    clearAuthError();

    const username =
        document
            .getElementById(
                "loginUsername"
            )
            .value;

    const password =
        document
            .getElementById(
                "loginPassword"
            )
            .value;

    try {

        const data = await api(
            "/api/login",
            {
                method: "POST",

                body: JSON.stringify({
                    username,
                    password
                })
            }
        );

        token = data.token;

        localStorage.setItem(
            "mtalk_token",
            token
        );

        await startApp();

    } catch (error) {

        showAuthError(
            error.message
        );
    }
}


// ============================================================
// LOGOUT
// ============================================================

function logout() {

    if (socket) {
        socket.disconnect();
        socket = null;
    }

    token = null;
    currentUser = null;
    currentChat = null;

    localStorage.removeItem(
        "mtalk_token"
    );

    document
        .getElementById("app")
        .classList.add("hidden");

    document
        .getElementById("authScreen")
        .classList.remove("hidden");

    showLogin();
}


// ============================================================
// START APP
// ============================================================

async function startApp() {

    try {

        const data =
            await api("/api/me");

        currentUser =
            data.user;

        document
            .getElementById("authScreen")
            .classList.add("hidden");

        document
            .getElementById("app")
            .classList.remove("hidden");

        document
            .getElementById("me")
            .textContent =
                "Вы: " +
                currentUser.username;

        connectSocket();

        await loadChats();

    } catch (error) {

        logout();
    }
}


// ============================================================
// SOCKET
// ============================================================

function connectSocket() {

    if (socket) {
        socket.disconnect();
    }

    socket = io({
        auth: {
            token
        }
    });

    socket.on(
        "connect",
        () => {
            if (currentChat) {
                socket.emit(
                    "joinChat",
                    currentChat
                );
            }
        }
    );

    socket.on(
        "message",
        message => {

            if (
                currentChat &&
                Number(message.chat_id) ===
                Number(currentChat)
            ) {

                addMessage(
                    message
                );
            }
        }
    );

    socket.on(
        "connect_error",
        error => {

            console.error(
                "Socket error:",
                error.message
            );
        }
    );
}


// ============================================================
// CHATS
// ============================================================

async function loadChats() {

    const data =
        await api("/api/chats");

    const list =
        document.getElementById(
            "chatList"
        );

    list.innerHTML = "";

    if (!data.chats.length) {

        list.innerHTML =
            '<div class="empty">' +
            "Пока нет чатов.<br>" +
            "Найдите пользователя сверху." +
            "</div>";

        return;
    }

    for (const chat of data.chats) {

        const div =
            document.createElement(
                "div"
            );

        div.className = "chat";

        div.dataset.id =
            chat.id;

        div.innerHTML =
            '<div class="chat-name">' +
            escapeHtml(
                chat.other_username
            ) +
            "</div>" +

            '<div class="chat-id">' +
            "Личный чат" +
            "</div>";

        div.onclick = () =>
            openChat(
                chat.id,
                chat.other_username
            );

        list.appendChild(div);
    }
}


// ============================================================
// SEARCH
// ============================================================

let searchTimer = null;

async function searchUsers() {

    clearTimeout(searchTimer);

    searchTimer =
        setTimeout(
            async () => {

                const q =
                    document
                        .getElementById(
                            "searchInput"
                        )
                        .value
                        .trim();

                if (!q) {

                    await loadChats();

                    return;
                }

                try {

                    const data =
                        await api(
                            "/api/users?q=" +
                            encodeURIComponent(q)
                        );

                    const list =
                        document
                            .getElementById(
                                "chatList"
                            );

                    list.innerHTML = "";

                    if (
                        !data.users.length
                    ) {

                        list.innerHTML =
                            '<div class="empty">' +
                            "Пользователи не найдены." +
                            "</div>";

                        return;
                    }

                    for (
                        const user
                        of data.users
                    ) {

                        const div =
                            document.createElement(
                                "div"
                            );

                        div.className =
                            "chat";

                        div.innerHTML =
                            '<div class="chat-name">' +
                            escapeHtml(
                                user.username
                            ) +
                            "</div>" +

                            '<div class="chat-id">' +
                            "Нажмите, чтобы открыть чат" +
                            "</div>";

                        div.onclick =
                            () =>
                                createChat(
                                    user.id,
                                    user.username
                                );

                        list.appendChild(
                            div
                        );
                    }

                } catch (error) {

                    console.error(
                        error
                    );
                }

            },
            250
        );
}


// ============================================================
// CREATE CHAT
// ============================================================

async function createChat(
    userId,
    username
) {

    try {

        const data =
            await api(
                "/api/chats",
                {
                    method: "POST",

                    body: JSON.stringify({
                        userId
                    })
                }
            );

        document
            .getElementById(
                "searchInput"
            )
            .value = "";

        await loadChats();

        openChat(
            data.chat.id,
            username
        );

    } catch (error) {

        alert(
            error.message
        );
    }
}


// ============================================================
// OPEN CHAT
// ============================================================

async function openChat(
    chatId,
    username
) {

    currentChat =
        Number(chatId);

    document
        .getElementById(
            "chatTitle"
        )
        .textContent =
            username;

    document
        .getElementById(
            "messageInput"
        )
        .disabled = false;

    document
        .getElementById(
            "sendButton"
        )
        .disabled = false;

    document
        .getElementById(
            "app"
        )
        .classList.add(
            "chat-open"
        );

    if (socket) {

        socket.emit(
            "joinChat",
            currentChat
        );
    }

    const chatItems =
        document.querySelectorAll(
            ".chat"
        );

    chatItems.forEach(
        item => {

            item.classList.toggle(
                "active",
                Number(
                    item.dataset.id
                ) === currentChat
            );
        }
    );

    await loadMessages();
}


// ============================================================
// CLOSE MOBILE CHAT
// ============================================================

function closeChat() {

    document
        .getElementById(
            "app"
        )
        .classList.remove(
            "chat-open"
        );
}


// ============================================================
// LOAD MESSAGES
// ============================================================

async function loadMessages() {

    if (!currentChat) {
        return;
    }

    try {

        const data =
            await api(
                "/api/chats/" +
                currentChat +
                "/messages"
            );

        const box =
            document.getElementById(
                "messages"
            );

        box.innerHTML = "";

        if (!data.messages.length) {

            box.innerHTML =
                '<div class="empty">' +
                "Сообщений пока нет.<br>" +
                "Напишите первым!" +
                "</div>";

            return;
        }

        for (
            const message
            of data.messages
        ) {

            addMessage(
                message,
                false
            );
        }

        scrollMessages();

    } catch (error) {

        console.error(
            error
        );
    }
}


// ============================================================
// ADD MESSAGE
// ============================================================

function addMessage(
    message,
    scroll = true
) {

    const box =
        document.getElementById(
            "messages"
        );

    const empty =
        box.querySelector(
            ".empty"
        );

    if (empty) {
        empty.remove();
    }

    if (
        box.querySelector(
            '[data-message-id="' +
            message.id +
            '"]'
        )
    ) {
        return;
    }

    const div =
        document.createElement(
            "div"
        );

    div.className =
        "message";

    div.dataset.messageId =
        message.id;

    if (
        Number(message.sender_id) ===
        Number(currentUser.id)
    ) {

        div.classList.add(
            "mine"
        );
    }

    const date =
        new Date(
            Number(
                message.created_at
            )
        );

    const time =
        date.toLocaleTimeString(
            "ru-RU",
            {
                hour: "2-digit",
                minute: "2-digit"
            }
        );

    div.innerHTML =
        '<div class="message-user">' +
        escapeHtml(
            message.sender_username
        ) +
        "</div>" +

        '<div class="message-text">' +
        escapeHtml(
            message.text
        ) +
        "</div>" +

        '<div class="message-time">' +
        time +
        "</div>";

    box.appendChild(
        div
    );

    if (scroll) {
        scrollMessages();
    }
}


// ============================================================
// SEND MESSAGE
// ============================================================

function sendMessage() {

    if (!socket) {
        return;
    }

    if (!currentChat) {
        return;
    }

    const input =
        document.getElementById(
            "messageInput"
        );

    const text =
        input.value.trim();

    if (!text) {
        return;
    }

    socket.emit(
        "sendMessage",
        {
            chatId: currentChat,
            text
        }
    );

    input.value = "";

    input.focus();
}


// ============================================================
// ENTER
// ============================================================

function messageKey(event) {

    if (
        event.key === "Enter" &&
        !event.shiftKey
    ) {

        event.preventDefault();

        sendMessage();
    }
}


// ============================================================
// SCROLL
// ============================================================

function scrollMessages() {

    const box =
        document.getElementById(
            "messages"
        );

    box.scrollTop =
        box.scrollHeight;
}


// ============================================================
// ESCAPE HTML
// ============================================================

function escapeHtml(text) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        text;

    return div.innerHTML;
}


// ============================================================
// START
// ============================================================

if (token) {

    startApp();

} else {

    showLogin();
}

</script>

</body>
</html>`;

// ============================================================
// FRONTEND ROUTE
// ============================================================

app.get("/", (req, res) => {
    res.type("html").send(HTML);
});

// ============================================================
// SOCKET.IO AUTH
// ============================================================

io.use((socket, next) => {

    try {

        const token =
            socket.handshake.auth &&
            socket.handshake.auth.token;

        if (!token) {
            return next(
                new Error(
                    "Необходима авторизация"
                )
            );
        }

        const payload =
            jwt.verify(
                token,
                JWT_SECRET
            );

        socket.user = payload;

        next();

    } catch (error) {

        next(
            new Error(
                "Недействительный токен"
            )
        );
    }
});

// ============================================================
// SOCKET EVENTS
// ============================================================

io.on("connection", (socket) => {

    console.log(
        "Socket connected:",
        socket.user.username
    );

    socket.on(
        "joinChat",
        (chatId) => {

            const id =
                Number(chatId);

            if (!Number.isInteger(id)) {
                return;
            }

            if (
                !userIsInChat(
                    socket.user.id,
                    id
                )
            ) {
                return;
            }

            socket.join(
                "chat_" + id
            );
        }
    );


    socket.on(
        "sendMessage",
        (data) => {

            try {

                const chatId =
                    Number(
                        data &&
                        data.chatId
                    );

                const text =
                    String(
                        data &&
                        data.text ||
                        ""
                    )
                        .trim()
                        .slice(0, 4000);

                if (
                    !Number.isInteger(
                        chatId
                    )
                ) {
                    return;
                }

                if (!text) {
                    return;
                }

                if (
                    !userIsInChat(
                        socket.user.id,
                        chatId
                    )
                ) {
                    return;
                }

                const result =
                    db
                        .prepare(
                            `
                            INSERT INTO messages
                            (
                                chat_id,
                                sender_id,
                                text,
                                created_at
                            )
                            VALUES (?, ?, ?, ?)
                            `
                        )
                        .run(
                            chatId,
                            socket.user.id,
                            text,
                            Date.now()
                        );

                const message =
                    db
                        .prepare(
                            `
                            SELECT
                                m.id,
                                m.chat_id,
                                m.sender_id,
                                m.text,
                                m.created_at,
                                u.username
                                    AS sender_username
                            FROM messages m
                            JOIN users u
                                ON u.id =
                                   m.sender_id
                            WHERE m.id = ?
                            `
                        )
                        .get(
                            result.lastInsertRowid
                        );

                io.to(
                    "chat_" + chatId
                ).emit(
                    "message",
                    message
                );

            } catch (error) {

                console.error(
                    "SEND MESSAGE ERROR:",
                    error
                );
            }
        }
    );


    socket.on(
        "disconnect",
        () => {

            console.log(
                "Socket disconnected:",
                socket.user.username
            );
        }
    );
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "EXPRESS ERROR:",
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        res.status(500).json({
            error: "Внутренняя ошибка сервера.",
        });
    }
);

// ============================================================
// START
// ============================================================

server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "================================"
        );

        console.log(
            "M-Talk running on port " +
            PORT
        );

        console.log(
            "M-Talk is ready!"
        );

        console.log(
            "================================"
        );
    }
);

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

function shutdown(signal) {

    console.log(
        signal +
        " received. Shutting down..."
    );

    server.close(() => {

        try {
            db.close();
        } catch (e) {}

        process.exit(0);
    });
}

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);
