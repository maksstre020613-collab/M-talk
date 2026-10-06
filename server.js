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

const app = express();

app.set("trust proxy", 1);

const server = http.createServer(app);

const io = new Server(server, {
    maxHttpBufferSize: 10 * 1024 * 1024
});

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

const db = new Database(
    path.join(DATA_DIR, "mtalk.db")
);

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

    FOREIGN KEY(user1_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY(user2_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    UNIQUE(user1_id, user2_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL,

    FOREIGN KEY(chat_id)
        REFERENCES chats(id)
        ON DELETE CASCADE,

    FOREIGN KEY(sender_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_chat
ON messages(chat_id, id);

CREATE INDEX IF NOT EXISTS idx_users_username
ON users(username);

CREATE INDEX IF NOT EXISTS idx_chats_user1
ON chats(user1_id);

CREATE INDEX IF NOT EXISTS idx_chats_user2
ON chats(user2_id);
`);

// ============================================================
// DATABASE MIGRATION
// ============================================================

const columns = db
    .prepare("PRAGMA table_info(messages)")
    .all()
    .map(x => x.name);

if (!columns.includes("type")) {
    db.exec(`
        ALTER TABLE messages
        ADD COLUMN type TEXT NOT NULL DEFAULT 'text'
    `);
}

if (!columns.includes("media_data")) {
    db.exec(`
        ALTER TABLE messages
        ADD COLUMN media_data TEXT
    `);
}

// ============================================================
// SECURITY
// ============================================================

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],

                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'"
                ],

                scriptSrcAttr: [
                    "'unsafe-inline'"
                ],

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
                    "data:",
                    "blob:"
                ],

                mediaSrc: [
                    "'self'",
                    "blob:"
                ],

                objectSrc: ["'none'"],

                baseUri: ["'self'"],

                frameAncestors: ["'none'"]
            }
        }
    })
);

app.use(
    express.json({
        limit: "12mb"
    })
);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        error:
            "Слишком много попыток. Попробуйте позже."
    }
});

// ============================================================
// HELPERS
// ============================================================

function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            username: user.username
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

function authMiddleware(req, res, next) {

    try {

        const header =
            req.headers.authorization;

        if (
            !header ||
            !header.startsWith("Bearer ")
        ) {
            return res.status(401).json({
                error:
                    "Необходима авторизация"
            });
        }

        const token =
            header.substring(7);

        req.user =
            jwt.verify(
                token,
                JWT_SECRET
            );

        next();

    } catch (error) {

        res.status(401).json({
            error:
                "Недействительный или просроченный токен"
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
        .prepare(`
            SELECT
                id,
                username,
                created_at
            FROM users
            WHERE id = ?
        `)
        .get(id);
}

function getChatForUsers(a, b) {

    const user1 =
        Math.min(a, b);

    const user2 =
        Math.max(a, b);

    return db
        .prepare(`
            SELECT *
            FROM chats
            WHERE user1_id = ?
              AND user2_id = ?
        `)
        .get(
            user1,
            user2
        );
}

function userIsInChat(
    userId,
    chatId
) {

    return db
        .prepare(`
            SELECT id
            FROM chats
            WHERE id = ?
              AND (
                  user1_id = ?
                  OR
                  user2_id = ?
              )
        `)
        .get(
            chatId,
            userId,
            userId
        );
}

// ============================================================
// REGISTER
// ============================================================

app.post(
    "/api/register",
    authLimiter,
    async (req, res) => {

        try {

            let {
                username,
                password
            } = req.body;

            username =
                normalizeUsername(
                    username
                );

            password =
                String(
                    password || ""
                );

            if (
                username.length < 3 ||
                username.length > 24
            ) {

                return res.status(400).json({
                    error:
                        "Имя пользователя должно содержать от 3 до 24 символов."
                });
            }

            if (
                !/^[a-zA-Zа-яА-ЯёЁ0-9_]+$/
                    .test(username)
            ) {

                return res.status(400).json({
                    error:
                        "В имени можно использовать буквы, цифры и _."
                });
            }

            if (
                password.length < 6 ||
                password.length > 128
            ) {

                return res.status(400).json({
                    error:
                        "Пароль должен содержать от 6 до 128 символов."
                });
            }

            const exists =
                db
                    .prepare(`
                        SELECT id
                        FROM users
                        WHERE username = ?
                        COLLATE NOCASE
                    `)
                    .get(username);

            if (exists) {

                return res.status(409).json({
                    error:
                        "Такой пользователь уже существует."
                });
            }

            const hash =
                await bcrypt.hash(
                    password,
                    10
                );

            const result =
                db
                    .prepare(`
                        INSERT INTO users
                        (
                            username,
                            password_hash,
                            created_at
                        )
                        VALUES (?, ?, ?)
                    `)
                    .run(
                        username,
                        hash,
                        Date.now()
                    );

            const user =
                getUserById(
                    result.lastInsertRowid
                );

            const token =
                createToken(user);

            res.json({
                ok: true,
                token,
                user
            });

        } catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Ошибка сервера."
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

            let {
                username,
                password
            } = req.body;

            username =
                normalizeUsername(
                    username
                );

            password =
                String(
                    password || ""
                );

            const user =
                db
                    .prepare(`
                        SELECT *
                        FROM users
                        WHERE username = ?
                        COLLATE NOCASE
                    `)
                    .get(username);

            if (!user) {

                return res.status(401).json({
                    error:
                        "Неверный логин или пароль."
                });
            }

            const valid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!valid) {

                return res.status(401).json({
                    error:
                        "Неверный логин или пароль."
                });
            }

            const publicUser = {
                id: user.id,
                username: user.username,
                created_at:
                    user.created_at
            };

            res.json({
                ok: true,
                token:
                    createToken(
                        publicUser
                    ),
                user: publicUser
            });

        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Ошибка сервера."
            });
        }
    }
);

// ============================================================
// ME
// ============================================================

app.get(
    "/api/me",
    authMiddleware,
    (req, res) => {

        const user =
            getUserById(
                req.user.id
            );

        if (!user) {

            return res.status(404).json({
                error:
                    "Пользователь не найден."
            });
        }

        res.json({
            user
        });
    }
);

// ============================================================
// USERS
// ============================================================

app.get(
    "/api/users",
    authMiddleware,
    (req, res) => {

        try {

            const q =
                String(
                    req.query.q || ""
                )
                    .trim()
                    .slice(0, 30);

            if (!q) {

                return res.json({
                    users: []
                });
            }

            const users =
                db
                    .prepare(`
                        SELECT
                            id,
                            username,
                            created_at
                        FROM users
                        WHERE username LIKE ?
                          AND id != ?
                        ORDER BY username
                        LIMIT 20
                    `)
                    .all(
                        `%${q}%`,
                        req.user.id
                    );

            res.json({
                users
            });

        } catch (error) {

            console.error(
                "SEARCH ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Ошибка сервера."
            });
        }
    }
);

// ============================================================
// CHATS
// ============================================================

app.get(
    "/api/chats",
    authMiddleware,
    (req, res) => {

        try {

            const chats =
                db
                    .prepare(`
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
                            ON u1.id =
                               c.user1_id

                        JOIN users u2
                            ON u2.id =
                               c.user2_id

                        WHERE
                            c.user1_id = @userId
                            OR
                            c.user2_id = @userId

                        ORDER BY c.id DESC
                    `)
                    .all({
                        userId:
                            req.user.id
                    });

            res.json({
                chats
            });

        } catch (error) {

            console.error(
                "CHATS ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Ошибка сервера."
            });
        }
    }
);

// ============================================================
// CREATE CHAT
// ============================================================

app.post(
    "/api/chats",
    authMiddleware,
    (req, res) => {

        try {

            const otherUserId =
                Number(
                    req.body.userId
                );

            if (
                !Number.isInteger(
                    otherUserId
                )
            ) {

                return res.status(400).json({
                    error:
                        "Неверный пользователь."
                });
            }

            if (
                otherUserId ===
                req.user.id
            ) {

                return res.status(400).json({
                    error:
                        "Нельзя создать чат с самим собой."
                });
            }

            const other =
                getUserById(
                    otherUserId
                );

            if (!other) {

                return res.status(404).json({
                    error:
                        "Пользователь не найден."
                });
            }

            let chat =
                getChatForUsers(
                    req.user.id,
                    otherUserId
                );

            if (!chat) {

                const user1 =
                    Math.min(
                        req.user.id,
                        otherUserId
                    );

                const user2 =
                    Math.max(
                        req.user.id,
                        otherUserId
                    );

                const result =
                    db
                        .prepare(`
                            INSERT INTO chats
                            (
                                user1_id,
                                user2_id,
                                created_at
                            )
                            VALUES (?, ?, ?)
                        `)
                        .run(
                            user1,
                            user2,
                            Date.now()
                        );

                chat =
                    db
                        .prepare(`
                            SELECT *
                            FROM chats
                            WHERE id = ?
                        `)
                        .get(
                            result.lastInsertRowid
                        );
            }

            res.json({
                ok: true,

                chat: {
                    id: chat.id,
                    other_id:
                        other.id,
                    other_username:
                        other.username
                }
            });

        } catch (error) {

            console.error(
                "CREATE CHAT ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Ошибка сервера."
            });
        }
    }
);

// ============================================================
// MESSAGES
// ============================================================

app.get(
    "/api/chats/:id/messages",
    authMiddleware,
    (req, res) => {

        try {

            const chatId =
                Number(
                    req.params.id
                );

            if (
                !Number.isInteger(
                    chatId
                )
            ) {

                return res.status(400).json({
                    error:
                        "Неверный ID чата."
                });
            }

            if (
                !userIsInChat(
                    req.user.id,
                    chatId
                )
            ) {

                return res.status(403).json({
                    error:
                        "Нет доступа к этому чату."
                });
            }

            const messages =
                db
                    .prepare(`
                        SELECT
                            m.id,
                            m.chat_id,
                            m.sender_id,
                            m.text,
                            m.created_at,
                            m.type,
                            m.media_data,
                            u.username
                                AS sender_username

                        FROM messages m

                        JOIN users u
                            ON u.id =
                               m.sender_id

                        WHERE m.chat_id = ?

                        ORDER BY m.id ASC

                        LIMIT 200
                    `)
                    .all(chatId);

            res.json({
                messages
            });

        } catch (error) {

            console.error(
                "MESSAGES ERROR:",
                error
            );

            res.status(500).json({
                error:
                    "Ошибка сервера."
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
    content="width=device-width,
    initial-scale=1,
    maximum-scale=1,
    viewport-fit=cover"
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

    overflow: hidden;
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

/* ==========================================================
   AUTH
   ========================================================== */

.auth-screen {

    min-height: 100dvh;

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
        rgba(25, 29, 39, .95);

    box-shadow:
        0 20px 70px
        rgba(0,0,0,.45);

    animation:
        fadeUp .45s ease;
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

    border:
        1px solid #333b4d;

    border-radius: 13px;

    outline: none;

    color: white;

    background: #11151d;

    transition:
        border .2s,
        transform .2s,
        box-shadow .2s;
}

.input:focus {

    border-color: #5d8cff;

    box-shadow:
        0 0 0 3px
        rgba(93,140,255,.12);
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

    transition:
        transform .15s,
        background .2s;
}

.btn:hover {

    background: #628bff;

    transform:
        translateY(-1px);
}

.btn:active {

    transform:
        scale(.98);
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

/* ==========================================================
   APP
   ========================================================== */

.app {

    width: 100%;

    height: 100dvh;

    min-height: 0;

    display: flex;

    overflow: hidden;
}

.sidebar {

    width: 330px;

    flex-shrink: 0;

    border-right:
        1px solid #2b3241;

    background: #11151d;

    display: flex;

    flex-direction: column;

    min-height: 0;
}

.sidebar-head {

    padding: 20px;

    border-bottom:
        1px solid #2b3241;
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

.status {

    display: flex;

    align-items: center;

    gap: 6px;

    margin-top: 7px;

    font-size: 12px;

    color: #7f8aa0;
}

.status-dot {

    width: 7px;

    height: 7px;

    border-radius: 50%;

    background: #4ade80;

    box-shadow:
        0 0 8px
        rgba(74,222,128,.7);
}

.status-dot.offline {

    background: #777;

    box-shadow: none;
}

.header-buttons {

    display: flex;

    gap: 8px;

    margin-top: 12px;
}

.small-btn {

    border:
        1px solid #343c4c;

    border-radius: 10px;

    background: transparent;

    color: #b6bfce;

    padding: 8px 11px;

    transition: .2s;
}

.small-btn:hover {

    background: #202632;

    transform:
        translateY(-1px);
}

.search {

    padding: 12px;

    flex-shrink: 0;
}

.chat-list {

    overflow-y: auto;

    flex: 1;

    min-height: 0;
}

.chat {

    padding: 15px 18px;

    border-bottom:
        1px solid #202633;

    cursor: pointer;

    transition:
        background .2s,
        transform .15s;
}

.chat:hover {

    background: #191f2b;
}

.chat:active {

    transform:
        scale(.99);
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

/* ==========================================================
   MAIN
   ========================================================== */

.main {

    flex: 1;

    min-width: 0;

    min-height: 0;

    display: flex;

    flex-direction: column;

    position: relative;

    background:
        radial-gradient(
            circle at 20% 20%,
            rgba(79,124,255,.07),
            transparent 35%
        ),
        radial-gradient(
            circle at 80% 80%,
            rgba(130,80,255,.06),
            transparent 35%
        );
}

.chat-head {

    min-height: 72px;

    flex-shrink: 0;

    display: flex;

    align-items: center;

    padding: 15px 20px;

    border-bottom:
        1px solid #2b3241;

    background:
        rgba(21,26,35,.94);

    backdrop-filter:
        blur(12px);

    z-index: 5;
}

.chat-title {

    font-weight: 800;

    font-size: 18px;
}

.chat-subtitle {

    font-size: 11px;

    color: #768197;

    margin-top: 3px;
}

.messages {

    flex: 1;

    min-height: 0;

    overflow-y: auto;

    padding: 20px;

    scroll-behavior: smooth;

    position: relative;
}

.message {

    max-width: 75%;

    margin-bottom: 12px;

    padding: 10px 13px;

    border-radius: 15px;

    background: #202735;

    word-wrap: break-word;

    animation:
        messageIn .25s ease;

    box-shadow:
        0 5px 20px
        rgba(0,0,0,.08);
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

.message-text {

    white-space:
        pre-wrap;

    line-height: 1.35;
}

.voice-message {

    min-width: 220px;

    display: flex;

    align-items: center;

    gap: 10px;
}

.voice-play {

    width: 42px;

    height: 42px;

    border: 0;

    border-radius: 50%;

    background:
        rgba(255,255,255,.16);

    color: white;

    font-size: 17px;
}

.voice-wave {

    flex: 1;

    height: 25px;

    display: flex;

    align-items: center;

    gap: 3px;
}

.voice-wave i {

    width: 3px;

    border-radius: 5px;

    background:
        rgba(255,255,255,.65);

    animation:
        wave 1s ease-in-out infinite;

    animation-play-state: paused;
}

.voice-wave.playing i {

    animation-play-state: running;
}

.voice-wave i:nth-child(1) {
    height: 8px;
    animation-delay: .1s;
}

.voice-wave i:nth-child(2) {
    height: 17px;
    animation-delay: .2s;
}

.voice-wave i:nth-child(3) {
    height: 11px;
    animation-delay: .3s;
}

.voice-wave i:nth-child(4) {
    height: 22px;
    animation-delay: .4s;
}

.voice-wave i:nth-child(5) {
    height: 14px;
    animation-delay: .5s;
}

.voice-wave i:nth-child(6) {
    height: 19px;
    animation-delay: .6s;
}

.voice-wave i:nth-child(7) {
    height: 9px;
    animation-delay: .7s;
}

.voice-duration {

    font-size: 11px;

    opacity: .7;
}

/* ==========================================================
   TYPING
   ========================================================== */

.typing {

    position: absolute;

    left: 20px;

    bottom: 92px;

    padding: 7px 11px;

    border-radius: 12px;

    background:
        rgba(25,29,39,.92);

    color: #8e99ad;

    font-size: 12px;

    opacity: 0;

    transform:
        translateY(8px);

    transition:
        .2s;

    pointer-events: none;
}

.typing.show {

    opacity: 1;

    transform:
        translateY(0);
}

.typing-dots span {

    display: inline-block;

    animation:
        dot 1.2s infinite;
}

.typing-dots span:nth-child(2) {
    animation-delay: .15s;
}

.typing-dots span:nth-child(3) {
    animation-delay: .3s;
}

/* ==========================================================
   COMPOSER
   ========================================================== */

.composer {

    flex-shrink: 0;

    display: flex;

    align-items: center;

    gap: 9px;

    padding:
        10px 14px
        calc(10px + env(safe-area-inset-bottom))
        14px;

    border-top:
        1px solid #2b3241;

    background:
        rgba(21,26,35,.97);

    backdrop-filter:
        blur(15px);

    z-index: 10;
}

.composer input {

    flex: 1;

    min-width: 0;

    height: 48px;

    padding: 13px 15px;

    border:
        1px solid #343c4c;

    border-radius: 14px;

    background: #10141b;

    color: white;

    outline: none;

    transition: .2s;
}

.composer input:focus {

    border-color: #527ff0;

    box-shadow:
        0 0 0 3px
        rgba(82,127,240,.1);
}

.send,
.voice {

    width: 48px;

    height: 48px;

    flex-shrink: 0;

    border: 0;

    border-radius: 14px;

    color: white;

    font-size: 19px;

    transition:
        transform .15s,
        background .2s;
}

.send {

    background: #4f7cff;
}

.voice {

    background: #293243;
}

.send:hover,
.voice:hover {

    transform:
        translateY(-1px);
}

.send:active,
.voice:active {

    transform:
        scale(.94);
}

.voice.recording {

    background: #e74c5d;

    animation:
        recordPulse 1s infinite;
}

/* ==========================================================
   EMPTY
   ========================================================== */

.empty {

    height: 100%;

    display: flex;

    align-items: center;

    justify-content: center;

    color: #788398;

    text-align: center;

    padding: 20px;
}

/* ==========================================================
   SETTINGS
   ========================================================== */

.overlay {

    position: fixed;

    inset: 0;

    background:
        rgba(0,0,0,.55);

    backdrop-filter:
        blur(5px);

    z-index: 100;

    display: flex;

    align-items: center;

    justify-content: center;

    padding: 18px;

    animation:
        fade .2s ease;
}

.modal {

    width: 100%;

    max-width: 440px;

    max-height: 90dvh;

    overflow-y: auto;

    background: #171c27;

    border:
        1px solid #303849;

    border-radius: 22px;

    box-shadow:
        0 30px 100px
        rgba(0,0,0,.55);

    animation:
        fadeUp .25s ease;
}

.modal-head {

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding: 20px;

    border-bottom:
        1px solid #2b3241;
}

.modal-title {

    font-size: 21px;

    font-weight: 800;
}

.close {

    width: 36px;

    height: 36px;

    border: 0;

    border-radius: 10px;

    background: #242b39;

    color: white;

    font-size: 20px;
}

.modal-body {

    padding: 18px;
}

.setting {

    padding: 15px 0;

    border-bottom:
        1px solid #252d3b;
}

.setting:last-child {

    border-bottom: 0;
}

.setting-title {

    font-weight: 700;

    margin-bottom: 5px;
}

.setting-desc {

    font-size: 12px;

    color: #818ca0;

    margin-bottom: 12px;
}

.theme-grid,
.bg-grid {

    display: grid;

    grid-template-columns:
        repeat(2, 1fr);

    gap: 9px;
}

.theme-btn,
.bg-btn {

    padding: 13px;

    border:
        1px solid #343c4c;

    border-radius: 12px;

    background: #11151d;

    color: #c7cfdd;

    text-align: left;

    transition: .2s;
}

.theme-btn:hover,
.bg-btn:hover {

    border-color: #527ff0;

    transform:
        translateY(-1px);
}

.theme-btn.selected,
.bg-btn.selected {

    border-color: #5d8cff;

    box-shadow:
        0 0 0 2px
        rgba(93,140,255,.12);
}

.profile {

    display: flex;

    align-items: center;

    gap: 14px;
}

.avatar {

    width: 60px;

    height: 60px;

    border-radius: 50%;

    display: flex;

    align-items: center;

    justify-content: center;

    background:
        linear-gradient(
            135deg,
            #4f7cff,
            #8259e8
        );

    font-size: 23px;

    font-weight: 800;
}

.profile-name {

    font-size: 19px;

    font-weight: 800;
}

.profile-id {

    color: #7e899d;

    font-size: 12px;

    margin-top: 4px;
}

/* ==========================================================
   THEMES
   ========================================================== */

body.light {

    background:
        linear-gradient(
            135deg,
            #edf2fa,
            #ffffff
        );

    color: #18202c;
}

body.light .sidebar,
body.light .main,
body.light .chat-head,
body.light .composer {

    background:
        rgba(247,249,253,.96);

    color: #18202c;
}

body.light .sidebar,
body.light .chat-head,
body.light .composer {

    border-color: #d9dfeb;
}

body.light .input,
body.light .composer input {

    background: #fff;

    color: #18202c;

    border-color: #cdd5e3;
}

body.light .chat:hover {

    background: #edf1f7;
}

body.light .chat.active {

    background: #e2e9f6;
}

body.light .message {

    background: #e5eaf2;

    color: #18202c;
}

body.light .modal {

    background: #f7f9fd;

    color: #18202c;
}

body.amoled {

    background: #000;
}

body.amoled .sidebar,
body.amoled .main,
body.amoled .chat-head,
body.amoled .composer {

    background: #000;
}

body.amoled .message {

    background: #151515;
}

/* ==========================================================
   CHAT BACKGROUNDS
   ========================================================== */

.main.bg-stars {

    background:
        radial-gradient(
            circle at 20% 30%,
            rgba(100,140,255,.12),
            transparent 25%
        ),
        radial-gradient(
            circle at 80% 70%,
            rgba(170,90,255,.1),
            transparent 25%
        ),
        #10131a;
}

.main.bg-blue {

    background:
        linear-gradient(
            145deg,
            #101a32,
            #172746,
            #10131a
        );
}

.main.bg-purple {

    background:
        linear-gradient(
            145deg,
            #171125,
            #291744,
            #10131a
        );
}

.main.bg-green {

    background:
        linear-gradient(
            145deg,
            #0e211d,
            #15382f,
            #10131a
        );
}

/* ==========================================================
   ANIMATIONS
   ========================================================== */

@keyframes fade {

    from {
        opacity: 0;
    }

    to {
        opacity: 1;
    }
}

@keyframes fadeUp {

    from {
        opacity: 0;
        transform:
            translateY(15px)
            scale(.98);
    }

    to {
        opacity: 1;
        transform:
            translateY(0)
            scale(1);
    }
}

@keyframes messageIn {

    from {
        opacity: 0;
        transform:
            translateY(8px)
            scale(.98);
    }

    to {
        opacity: 1;
        transform:
            translateY(0)
            scale(1);
    }
}

@keyframes dot {

    0%,
    60%,
    100% {
        opacity: .25;
        transform: translateY(0);
    }

    30% {
        opacity: 1;
        transform: translateY(-3px);
    }
}

@keyframes wave {

    0%,
    100% {
        transform: scaleY(.55);
    }

    50% {
        transform: scaleY(1.2);
    }
}

@keyframes recordPulse {

    0%,
    100% {
        box-shadow:
            0 0 0 0
            rgba(231,76,93,.4);
    }

    50% {
        box-shadow:
            0 0 0 8px
            rgba(231,76,93,0);
    }
}

/* ==========================================================
   MOBILE
   ========================================================== */

.mobile-back {

    display: none;

    margin-right: 12px;

    border: 0;

    background: transparent;

    color: white;

    font-size: 22px;
}

@media (max-width: 700px) {

    .sidebar {

        width: 100%;
    }

    .main {

        display: none;
    }

    .app.chat-open
    .sidebar {

        display: none;
    }

    .app.chat-open
    .main {

        display: flex;
    }

    .mobile-back {

        display: block;
    }

    .message {

        max-width: 86%;
    }

    .messages {

        padding:
            14px 12px;
    }

    .chat-head {

        min-height: 64px;

        padding:
            10px 14px;
    }

    .composer {

        padding:
            8px 8px
            calc(
                8px +
                env(
                    safe-area-inset-bottom
                )
            );
    }

    .composer input {

        height: 46px;
    }

    .send,
    .voice {

        width: 46px;

        height: 46px;
    }
}

</style>

</head>

<body>

<!-- ========================================================
     AUTH
     ======================================================== -->

<div
    id="authScreen"
    class="auth-screen"
>

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
/>

<input
    id="loginPassword"
    class="input"
    type="password"
    placeholder="Пароль"
    autocomplete="current-password"
/>

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

<div
    id="registerForm"
    class="hidden"
>

<input
    id="registerUsername"
    class="input"
    placeholder="Имя пользователя"
    autocomplete="username"
/>

<input
    id="registerPassword"
    class="input"
    type="password"
    placeholder="Пароль"
    autocomplete="new-password"
/>

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

<div
    id="authError"
    class="error"
></div>

</div>

</div>


<!-- ========================================================
     APP
     ======================================================== -->

<div
    id="app"
    class="app hidden"
>

<aside class="sidebar">

<div class="sidebar-head">

<div class="sidebar-title">
M-Talk
</div>

<div
    id="me"
    class="me"
></div>

<div class="status">

<span
    id="statusDot"
    class="status-dot"
></span>

<span id="statusText">
Подключение...
</span>

</div>

<div class="header-buttons">

<button
    class="small-btn"
    onclick="openSettings()"
>
⚙️ Настройки
</button>

<button
    class="small-btn"
    onclick="logout()"
>
Выйти
</button>

</div>

</div>

<div class="search">

<input
    id="searchInput"
    class="input"
    placeholder="Найти пользователя..."
    oninput="searchUsers()"
/>

</div>

<div
    id="chatList"
    class="chat-list"
></div>

</aside>


<main
    id="main"
    class="main bg-stars"
>

<div class="chat-head">

<button
    class="mobile-back"
    onclick="closeChat()"
>
←
</button>

<div>

<div
    id="chatTitle"
    class="chat-title"
>
Выберите чат
</div>

<div
    id="chatSubtitle"
    class="chat-subtitle"
></div>

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

<div
    id="typing"
    class="typing"
>

<span id="typingName">
Пользователь
</span>

печатает
<span class="typing-dots">
<span>.</span>
<span>.</span>
<span>.</span>
</span>

</div>

<div class="composer">

<button
    id="voiceButton"
    class="voice"
    title="Голосовое сообщение"
    disabled
    onmousedown="startRecording()"
    onmouseup="stopRecording()"
    ontouchstart="startRecording(event)"
    ontouchend="stopRecording(event)"
>
🎙️
</button>

<input
    id="messageInput"
    placeholder="Написать сообщение..."
    onkeydown="messageKey(event)"
    oninput="typingInput()"
    disabled
/>

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


<!-- ========================================================
     SETTINGS
     ======================================================== -->

<div
    id="settingsOverlay"
    class="overlay hidden"
    onclick="overlayClick(event)"
>

<div class="modal">

<div class="modal-head">

<div class="modal-title">
Настройки
</div>

<button
    class="close"
    onclick="closeSettings()"
>
×
</button>

</div>

<div class="modal-body">

<div class="setting">

<div class="setting-title">
👤 Аккаунт
</div>

<div class="profile">

<div
    id="profileAvatar"
    class="avatar"
>
M
</div>

<div>

<div
    id="profileName"
    class="profile-name"
>
-
</div>

<div
    id="profileId"
    class="profile-id"
>
ID: -
</div>

</div>

</div>

</div>


<div class="setting">

<div class="setting-title">
🎨 Тема
</div>

<div class="setting-desc">
Выберите внешний вид M-Talk
</div>

<div class="theme-grid">

<button
    id="themeDark"
    class="theme-btn"
    onclick="setTheme('dark')"
>
🌙 Тёмная
</button>

<button
    id="themeLight"
    class="theme-btn"
    onclick="setTheme('light')"
>
☀️ Светлая
</button>

<button
    id="themeAmoled"
    class="theme-btn"
    onclick="setTheme('amoled')"
>
⚫ AMOLED
</button>

</div>

</div>


<div class="setting">

<div class="setting-title">
🌌 Фон чата
</div>

<div class="setting-desc">
Можно изменить фон области переписки
</div>

<div class="bg-grid">

<button
    id="bgStars"
    class="bg-btn"
    onclick="setChatBg('stars')"
>
✨ Космос
</button>

<button
    id="bgBlue"
    class="bg-btn"
    onclick="setChatBg('blue')"
>
🌊 Синий
</button>

<button
    id="bgPurple"
    class="bg-btn"
    onclick="setChatBg('purple')"
>
🔮 Фиолетовый
</button>

<button
    id="bgGreen"
    class="bg-btn"
    onclick="setChatBg('green')"
>
🌿 Зелёный
</button>

</div>

</div>


<div class="setting">

<div class="setting-title">
💬 M-Talk
</div>

<div class="setting-desc">
Современный интернет-мессенджер
</div>

</div>

</div>

</div>

</div>


<script src="/socket.io/socket.io.js"></script>

<script>

// ============================================================
// STATE
// ============================================================

let token =
    localStorage.getItem(
        "mtalk_token"
    );

let currentUser = null;

let currentChat = null;

let socket = null;

let typingTimer = null;

let typingSent = false;

let mediaRecorder = null;

let recordedChunks = [];

let recordingStarted = false;

let recordingStartTime = 0;


// ============================================================
// API
// ============================================================

async function api(
    url,
    options = {}
) {

    const headers = {

        "Content-Type":
            "application/json",

        ...(options.headers || {})
    };

    if (token) {

        headers.Authorization =
            "Bearer " + token;
    }

    const response =
        await fetch(
            url,
            {
                ...options,
                headers
            }
        );

    let data = {};

    try {

        data =
            await response.json();

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
        .getElementById(
            "loginForm"
        )
        .classList.remove(
            "hidden"
        );

    document
        .getElementById(
            "registerForm"
        )
        .classList.add(
            "hidden"
        );

    clearAuthError();
}

function showRegister() {

    document
        .getElementById(
            "loginForm"
        )
        .classList.add(
            "hidden"
        );

    document
        .getElementById(
            "registerForm"
        )
        .classList.remove(
            "hidden"
        );

    clearAuthError();
}

function showAuthError(
    text
) {

    document
        .getElementById(
            "authError"
        )
        .textContent =
            text;
}

function clearAuthError() {

    document
        .getElementById(
            "authError"
        )
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

        const data =
            await api(
                "/api/register",
                {
                    method: "POST",

                    body:
                        JSON.stringify({
                            username,
                            password
                        })
                }
            );

        token =
            data.token;

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

        const data =
            await api(
                "/api/login",
                {
                    method: "POST",

                    body:
                        JSON.stringify({
                            username,
                            password
                        })
                }
            );

        token =
            data.token;

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
        .getElementById(
            "app"
        )
        .classList.add(
            "hidden"
        );

    document
        .getElementById(
            "authScreen"
        )
        .classList.remove(
            "hidden"
        );

    showLogin();
}


// ============================================================
// START APP
// ============================================================

async function startApp() {

    try {

        const data =
            await api(
                "/api/me"
            );

        currentUser =
            data.user;

        document
            .getElementById(
                "authScreen"
            )
            .classList.add(
                "hidden"
            );

        document
            .getElementById(
                "app"
            )
            .classList.remove(
                "hidden"
            );

        document
            .getElementById(
                "me"
            )
            .textContent =
                "Вы: " +
                currentUser.username;

        updateProfile();

        loadPreferences();

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

    socket =
        io({
            auth: {
                token
            }
        });

    socket.on(
        "connect",
        () => {

            setConnection(
                true
            );

            if (currentChat) {

                socket.emit(
                    "joinChat",
                    currentChat
                );
            }
        }
    );

    socket.on(
        "disconnect",
        () => {

            setConnection(
                false
            );
        }
    );

    socket.on(
        "connect_error",
        () => {

            setConnection(
                false
            );
        }
    );

    socket.on(
        "message",
        message => {

            if (
                currentChat &&
                Number(
                    message.chat_id
                ) ===
                Number(
                    currentChat
                )
            ) {

                addMessage(
                    message
                );
            }
        }
    );

    socket.on(
        "typing",
        data => {

            if (
                !currentChat ||
                Number(
                    data.chatId
                ) !==
                Number(
                    currentChat
                )
            ) {
                return;
            }

            document
                .getElementById(
                    "typingName"
                )
                .textContent =
                    data.username;

            document
                .getElementById(
                    "typing"
                )
                .classList.toggle(
                    "show",
                    data.typing
                );
        }
    );
}

function setConnection(
    online
) {

    const dot =
        document
            .getElementById(
                "statusDot"
            );

    const text =
        document
            .getElementById(
                "statusText"
            );

    dot.classList.toggle(
        "offline",
        !online
    );

    text.textContent =
        online
            ? "Онлайн"
            : "Нет соединения";
}


// ============================================================
// CHATS
// ============================================================

async function loadChats() {

    const data =
        await api(
            "/api/chats"
        );

    const list =
        document
            .getElementById(
                "chatList"
            );

    list.innerHTML = "";

    if (
        !data.chats.length
    ) {

        list.innerHTML =
            '<div class="empty">' +
            "Пока нет чатов.<br>" +
            "Найдите пользователя сверху." +
            "</div>";

        return;
    }

    for (
        const chat
        of data.chats
    ) {

        const div =
            document.createElement(
                "div"
            );

        div.className =
            "chat";

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

        div.onclick =
            () =>
                openChat(
                    chat.id,
                    chat.other_username
                );

        list.appendChild(
            div
        );
    }
}


// ============================================================
// SEARCH
// ============================================================

let searchTimer = null;

async function searchUsers() {

    clearTimeout(
        searchTimer
    );

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
                            encodeURIComponent(
                                q
                            )
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

                    body:
                        JSON.stringify({
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
            "chatSubtitle"
        )
        .textContent =
            "Личный чат";

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
            "voiceButton"
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

    document
        .querySelectorAll(
            ".chat"
        )
        .forEach(
            item => {

                item.classList.toggle(
                    "active",
                    Number(
                        item.dataset.id
                    ) ===
                    currentChat
                );
            }
        );

    await loadMessages();
}


// ============================================================
// CLOSE CHAT
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
            document
                .getElementById(
                    "messages"
                );

        box.innerHTML = "";

        if (
            !data.messages.length
        ) {

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
        document
            .getElementById(
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
        Number(
            message.sender_id
        ) ===
        Number(
            currentUser.id
        )
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
                hour:
                    "2-digit",
                minute:
                    "2-digit"
            }
        );

    let content = "";

    if (
        message.type ===
        "voice" &&
        message.media_data
    ) {

        const safeData =
            message.media_data
                .replace(/"/g, "&quot;");

        content =
            '<div class="voice-message">' +

            '<button ' +
            'class="voice-play" ' +
            'onclick="playVoice(this, \\''
            +
            safeData +
            '\\')">' +
            "▶" +
            "</button>" +

            '<div class="voice-wave">' +

            "<i></i><i></i><i></i>" +
            "<i></i><i></i><i></i><i></i>" +

            "</div>" +

            '<span class="voice-duration">' +
            "🎙️" +
            "</span>" +

            "</div>";

    } else {

        content =
            '<div class="message-text">' +
            escapeHtml(
                message.text
            ) +
            "</div>";
    }

    div.innerHTML =
        '<div class="message-user">' +
        escapeHtml(
            message.sender_username
        ) +
        "</div>" +

        content +

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

    if (
        !socket ||
        !currentChat
    ) {
        return;
    }

    const input =
        document
            .getElementById(
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
            chatId:
                currentChat,

            text
        }
    );

    input.value = "";

    sendTyping(
        false
    );

    input.focus();
}


// ============================================================
// TYPING
// ============================================================

function typingInput() {

    if (!socket || !currentChat) {
        return;
    }

    if (!typingSent) {

        typingSent = true;

        socket.emit(
            "typing",
            {
                chatId:
                    currentChat,
                typing: true
            }
        );
    }

    clearTimeout(
        typingTimer
    );

    typingTimer =
        setTimeout(
            () => {

                sendTyping(
                    false
                );

            },
            1200
        );
}

function sendTyping(
    value
) {

    if (!socket || !currentChat) {
        return;
    }

    typingSent =
        value;

    socket.emit(
        "typing",
        {
            chatId:
                currentChat,

            typing:
                value
        }
    );
}


// ============================================================
// ENTER
// ============================================================

function messageKey(
    event
) {

    if (
        event.key === "Enter" &&
        !event.shiftKey
    ) {

        event.preventDefault();

        sendMessage();
    }
}


// ============================================================
// VOICE RECORDING
// ============================================================

async function startRecording(
    event
) {

    if (event) {
        event.preventDefault();
    }

    if (
        !currentChat ||
        recordingStarted
    ) {
        return;
    }

    if (
        !navigator.mediaDevices ||
        !navigator.mediaDevices.getUserMedia
    ) {

        alert(
            "Браузер не поддерживает запись голоса."
        );

        return;
    }

    try {

        const stream =
            await navigator
                .mediaDevices
                .getUserMedia({
                    audio: true
                });

        recordedChunks = [];

        let options = {};

        if (
            MediaRecorder.isTypeSupported(
                "audio/webm;codecs=opus"
            )
        ) {

            options = {
                mimeType:
                    "audio/webm;codecs=opus"
            };
        }

        mediaRecorder =
            new MediaRecorder(
                stream,
                options
            );

        mediaRecorder.ondataavailable =
            event => {

                if (
                    event.data &&
                    event.data.size > 0
                ) {

                    recordedChunks.push(
                        event.data
                    );
                }
            };

        mediaRecorder.onstop =
            async () => {

                stream
                    .getTracks()
                    .forEach(
                        track =>
                            track.stop()
                    );

                if (
                    recordedChunks.length
                ) {

                    const blob =
                        new Blob(
                            recordedChunks,
                            {
                                type:
                                    mediaRecorder
                                        .mimeType ||
                                    "audio/webm"
                            }
                        );

                    await sendVoice(
                        blob
                    );
                }
            };

        mediaRecorder.start();

        recordingStarted =
            true;

        recordingStartTime =
            Date.now();

        document
            .getElementById(
                "voiceButton"
            )
            .classList.add(
                "recording"
            );

        document
            .getElementById(
                "voiceButton"
            )
            .textContent =
                "⏺️";

    } catch (error) {

        console.error(
            error
        );

        alert(
            "Не удалось получить доступ к микрофону."
        );
    }
}

function stopRecording(
    event
) {

    if (event) {
        event.preventDefault();
    }

    if (
        !recordingStarted ||
        !mediaRecorder
    ) {
        return;
    }

    const duration =
        Date.now() -
        recordingStartTime;

    recordingStarted =
        false;

    document
        .getElementById(
            "voiceButton"
        )
        .classList.remove(
            "recording"
        );

    document
        .getElementById(
            "voiceButton"
        )
        .textContent =
            "🎙️";

    if (
        mediaRecorder.state !==
        "inactive"
    ) {

        mediaRecorder.stop();
    }

    if (
        duration < 500
    ) {

        recordedChunks = [];
    }
}

async function sendVoice(
    blob
) {

    if (
        !currentChat ||
        !socket
    ) {
        return;
    }

    if (
        blob.size >
        7 * 1024 * 1024
    ) {

        alert(
            "Голосовое получилось слишком большим."
        );

        return;
    }

    const reader =
        new FileReader();

    reader.onload =
        () => {

            socket.emit(
                "sendVoice",
                {
                    chatId:
                        currentChat,

                    data:
                        reader.result
                }
            );
        };

    reader.readAsDataURL(
        blob
    );
}


// ============================================================
// PLAY VOICE
// ============================================================

function playVoice(
    button,
    data
) {

    try {

        const message =
            button.closest(
                ".message"
            );

        const wave =
            message.querySelector(
                ".voice-wave"
            );

        const audio =
            new Audio(
                data
            );

        wave.classList.add(
            "playing"
        );

        button.textContent =
            "⏸";

        audio.play();

        audio.onended =
            () => {

                wave.classList.remove(
                    "playing"
                );

                button.textContent =
                    "▶";
            };

    } catch (error) {

        console.error(
            error
        );
    }
}


// ============================================================
// SCROLL
// ============================================================

function scrollMessages() {

    const box =
        document
            .getElementById(
                "messages"
            );

    requestAnimationFrame(
        () => {

            box.scrollTop =
                box.scrollHeight;
        }
    );
}


// ============================================================
// SETTINGS
// ============================================================

function openSettings() {

    updateProfile();

    document
        .getElementById(
            "settingsOverlay"
        )
        .classList.remove(
            "hidden"
        );
}

function closeSettings() {

    document
        .getElementById(
            "settingsOverlay"
        )
        .classList.add(
            "hidden"
        );
}

function overlayClick(
    event
) {

    if (
        event.target.id ===
        "settingsOverlay"
    ) {

        closeSettings();
    }
}

function updateProfile() {

    if (!currentUser) {
        return;
    }

    document
        .getElementById(
            "profileName"
        )
        .textContent =
            currentUser.username;

    document
        .getElementById(
            "profileId"
        )
        .textContent =
            "ID: " +
            currentUser.id;

    document
        .getElementById(
            "profileAvatar"
        )
        .textContent =
            currentUser
                .username
                .charAt(0)
                .toUpperCase();
}


// ============================================================
// THEMES
// ============================================================

function setTheme(
    theme
) {

    document.body.classList.remove(
        "light",
        "amoled"
    );

    if (
        theme === "light"
    ) {

        document.body.classList.add(
            "light"
        );
    }

    if (
        theme === "amoled"
    ) {

        document.body.classList.add(
            "amoled"
        );
    }

    localStorage.setItem(
        "mtalk_theme",
        theme
    );

    updateThemeButtons();
}

function updateThemeButtons() {

    const theme =
        localStorage.getItem(
            "mtalk_theme"
        ) ||
        "dark";

    document
        .querySelectorAll(
            ".theme-btn"
        )
        .forEach(
            button =>
                button.classList.remove(
                    "selected"
                )
        );

    const active =
        document.getElementById(
            "theme" +
            theme.charAt(0).toUpperCase() +
            theme.slice(1)
        );

    if (active) {

        active.classList.add(
            "selected"
        );
    }
}


// ============================================================
// CHAT BACKGROUND
// ============================================================

function setChatBg(
    bg
) {

    const main =
        document.getElementById(
            "main"
        );

    main.classList.remove(
        "bg-stars",
        "bg-blue",
        "bg-purple",
        "bg-green"
    );

    main.classList.add(
        "bg-" + bg
    );

    localStorage.setItem(
        "mtalk_bg",
        bg
    );

    updateBgButtons();
}

function updateBgButtons() {

    const bg =
        localStorage.getItem(
            "mtalk_bg"
        ) ||
        "stars";

    document
        .querySelectorAll(
            ".bg-btn"
        )
        .forEach(
            button =>
                button.classList.remove(
                    "selected"
                )
        );

    const active =
        document.getElementById(
            "bg" +
            bg.charAt(0).toUpperCase() +
            bg.slice(1)
        );

    if (active) {

        active.classList.add(
            "selected"
        );
    }
}

function loadPreferences() {

    const theme =
        localStorage.getItem(
            "mtalk_theme"
        ) ||
        "dark";

    const bg =
        localStorage.getItem(
            "mtalk_bg"
        ) ||
        "stars";

    setTheme(
        theme
    );

    setChatBg(
        bg
    );
}


// ============================================================
// ESCAPE HTML
// ============================================================

function escapeHtml(
    text
) {

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
// ROUTE
// ============================================================

app.get(
    "/",
    (req, res) => {

        res
            .type("html")
            .send(HTML);
    }
);

// ============================================================
// SOCKET AUTH
// ============================================================

io.use(
    (socket, next) => {

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

            socket.user =
                jwt.verify(
                    token,
                    JWT_SECRET
                );

            next();

        } catch (error) {

            next(
                new Error(
                    "Недействительный токен"
                )
            );
        }
    }
);

// ============================================================
// SOCKET
// ============================================================

io.on(
    "connection",
    socket => {

        console.log(
            "Socket connected:",
            socket.user.username
        );

        socket.on(
            "joinChat",
            chatId => {

                const id =
                    Number(chatId);

                if (
                    !Number.isInteger(id)
                ) {
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
            "typing",
            data => {

                const chatId =
                    Number(
                        data &&
                        data.chatId
                    );

                if (
                    !Number.isInteger(
                        chatId
                    )
                ) {
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

                socket
                    .to(
                        "chat_" +
                        chatId
                    )
                    .emit(
                        "typing",
                        {
                            chatId,

                            username:
                                socket.user
                                    .username,

                            typing:
                                Boolean(
                                    data.typing
                                )
                        }
                    );
            }
        );

        socket.on(
            "sendMessage",
            data => {

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
                            .slice(
                                0,
                                4000
                            );

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
                            .prepare(`
                                INSERT INTO messages
                                (
                                    chat_id,
                                    sender_id,
                                    text,
                                    created_at,
                                    type
                                )
                                VALUES
                                (?, ?, ?, ?, 'text')
                            `)
                            .run(
                                chatId,
                                socket.user.id,
                                text,
                                Date.now()
                            );

                    const message =
                        db
                            .prepare(`
                                SELECT
                                    m.id,
                                    m.chat_id,
                                    m.sender_id,
                                    m.text,
                                    m.created_at,
                                    m.type,
                                    m.media_data,
                                    u.username
                                        AS sender_username

                                FROM messages m

                                JOIN users u
                                    ON u.id =
                                       m.sender_id

                                WHERE m.id = ?
                            `)
                            .get(
                                result.lastInsertRowid
                            );

                    io.to(
                        "chat_" +
                        chatId
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
            "sendVoice",
            data => {

                try {

                    const chatId =
                        Number(
                            data &&
                            data.chatId
                        );

                    const mediaData =
                        String(
                            data &&
                            data.data ||
                            ""
                        );

                    if (
                        !Number.isInteger(
                            chatId
                        )
                    ) {
                        return;
                    }

                    if (
                        !mediaData ||
                        mediaData.length >
                        9 * 1024 * 1024
                    ) {
                        return;
                    }

                    if (
                        !mediaData.startsWith(
                            "data:audio/"
                        )
                    ) {
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
                            .prepare(`
                                INSERT INTO messages
                                (
                                    chat_id,
                                    sender_id,
                                    text,
                                    created_at,
                                    type,
                                    media_data
                                )
                                VALUES
                                (?, ?, '', ?, 'voice', ?)
                            `)
                            .run(
                                chatId,
                                socket.user.id,
                                Date.now(),
                                mediaData
                            );

                    const message =
                        db
                            .prepare(`
                                SELECT
                                    m.id,
                                    m.chat_id,
                                    m.sender_id,
                                    m.text,
                                    m.created_at,
                                    m.type,
                                    m.media_data,
                                    u.username
                                        AS sender_username

                                FROM messages m

                                JOIN users u
                                    ON u.id =
                                       m.sender_id

                                WHERE m.id = ?
                            `)
                            .get(
                                result.lastInsertRowid
                            );

                    io.to(
                        "chat_" +
                        chatId
                    ).emit(
                        "message",
                        message
                    );

                } catch (error) {

                    console.error(
                        "VOICE ERROR:",
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
    }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "EXPRESS ERROR:",
            err
        );

        if (
            res.headersSent
        ) {

            return next(err);
        }

        res.status(500).json({
            error:
                "Внутренняя ошибка сервера."
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
            "M-Talk v3 running on port " +
            PORT
        );

        console.log(
            "Voice messages enabled"
        );

        console.log(
            "================================"
        );
    }
);

// ============================================================
// SHUTDOWN
// ============================================================

function shutdown(
    signal
) {

    console.log(
        signal +
        " received. Shutting down..."
    );

    server.close(
        () => {

            try {
                db.close();
            } catch (e) {}

            process.exit(0);
        }
    );
}

process.on(
    "SIGTERM",
    () =>
        shutdown(
            "SIGTERM"
        )
);

process.on(
    "SIGINT",
    () =>
        shutdown(
            "SIGINT"
        )
);
