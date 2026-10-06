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
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing");
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
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
app.use(express.static("public"));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30
});

app.use("/api/register", limiter);
app.use("/api/login", limiter);

async function query(sql, params = []) {
  return pool.query(sql, params);
}

async function initDB() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY(chat_id, user_id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS messages_chat_idx
    ON messages(chat_id, id)
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS members_user_idx
    ON chat_members(user_id)
  `);

  console.log("PostgreSQL database ready");
}

function token(user) {
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
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      error: "Недействительный токен"
    });
  }
}

async function member(chatId, userId) {
  const result = await query(
    `
    SELECT 1
    FROM chat_members
    WHERE chat_id=$1 AND user_id=$2
    `,
    [chatId, userId]
  );

  return result.rowCount > 0;
}

/* REGISTER */

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Логин: 3–20 символов, буквы, цифры и _"
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        error: "Пароль минимум 4 символа"
      });
    }

    const exists = await query(
      "SELECT id FROM users WHERE LOWER(username)=LOWER($1)",
      [username]
    );

    if (exists.rowCount) {
      return res.status(409).json({
        error: "Такой аккаунт уже существует"
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await query(
      `
      INSERT INTO users(username,password_hash)
      VALUES($1,$2)
      RETURNING id,username
      `,
      [username, hash]
    );

    const user = result.rows[0];

    res.json({
      token: token(user),
      user
    });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* LOGIN */

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const result = await query(
      `
      SELECT id,username,password_hash
      FROM users
      WHERE LOWER(username)=LOWER($1)
      `,
      [username]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Неверный логин или пароль"
      });
    }

    const user = result.rows[0];

    if (!(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Неверный логин или пароль"
      });
    }

    res.json({
      token: token(user),
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  }
});

/* ME */

app.get("/api/me", auth, async (req, res) => {
  const result = await query(
    `
    SELECT id,username,created_at
    FROM users
    WHERE id=$1
    `,
    [req.user.id]
  );

  if (!result.rowCount) {
    return res.status(404).json({
      error: "Пользователь не найден"
    });
  }

  res.json(result.rows[0]);
});

/* USERS */

app.get("/api/users", auth, async (req, res) => {
  const q = String(req.query.q || "").trim();

  if (!q) return res.json([]);

  const result = await query(
    `
    SELECT id,username
    FROM users
    WHERE id<>$1
      AND username ILIKE $2
    ORDER BY username
    LIMIT 20
    `,
    [req.user.id, `%${q}%`]
  );

  res.json(result.rows);
});

/* CREATE CHAT */

app.post("/api/chats", auth, async (req, res) => {
  const otherId = Number(req.body.userId);

  if (!Number.isInteger(otherId) || otherId === req.user.id) {
    return res.status(400).json({
      error: "Неверный пользователь"
    });
  }

  const other = await query(
    "SELECT id,username FROM users WHERE id=$1",
    [otherId]
  );

  if (!other.rowCount) {
    return res.status(404).json({
      error: "Пользователь не найден"
    });
  }

  const existing = await query(
    `
    SELECT c.id
    FROM chats c
    JOIN chat_members a ON a.chat_id=c.id
    JOIN chat_members b ON b.chat_id=c.id
    WHERE a.user_id=$1
      AND b.user_id=$2
    LIMIT 1
    `,
    [req.user.id, otherId]
  );

  if (existing.rowCount) {
    return res.json({
      id: existing.rows[0].id,
      user: other.rows[0]
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const chat = await client.query(
      "INSERT INTO chats DEFAULT VALUES RETURNING id"
    );

    const chatId = chat.rows[0].id;

    await client.query(
      `
      INSERT INTO chat_members(chat_id,user_id)
      VALUES($1,$2),($1,$3)
      `,
      [chatId, req.user.id, otherId]
    );

    await client.query("COMMIT");

    res.json({
      id: chatId,
      user: other.rows[0]
    });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);

    res.status(500).json({
      error: "Ошибка сервера"
    });
  } finally {
    client.release();
  }
});

/* CHATS */

app.get("/api/chats", auth, async (req, res) => {
  const result = await query(
    `
    SELECT
      c.id,
      u.id AS user_id,
      u.username,
      lm.text AS last_message,
      lm.created_at AS last_message_at
    FROM chats c

    JOIN chat_members me
      ON me.chat_id=c.id
     AND me.user_id=$1

    JOIN chat_members other
      ON other.chat_id=c.id
     AND other.user_id<>$1

    JOIN users u
      ON u.id=other.user_id

    LEFT JOIN LATERAL (
      SELECT text,created_at
      FROM messages
      WHERE chat_id=c.id
      ORDER BY id DESC
      LIMIT 1
    ) lm ON true

    ORDER BY COALESCE(lm.created_at,c.created_at) DESC
    `,
    [req.user.id]
  );

  res.json(result.rows);
});

/* MESSAGES */

app.get("/api/chats/:id/messages", auth, async (req, res) => {
  const chatId = Number(req.params.id);

  if (!(await member(chatId, req.user.id))) {
    return res.status(403).json({
      error: "Нет доступа"
    });
  }

  const result = await query(
    `
    SELECT
      m.id,
      m.chat_id,
      m.sender_id,
      u.username AS sender_username,
      m.text,
      m.created_at
    FROM messages m
    JOIN users u ON u.id=m.sender_id
    WHERE m.chat_id=$1
    ORDER BY m.id ASC
    LIMIT 200
    `,
    [chatId]
  );

  res.json(result.rows);
});

/* SOCKET */

io.use((socket, next) => {
  try {
    socket.user = jwt.verify(
      socket.handshake.auth?.token,
      JWT_SECRET
    );

    next();
  } catch {
    next(new Error("Авторизация не пройдена"));
  }
});

io.on("connection", socket => {
  socket.on("joinChat", async chatId => {
    chatId = Number(chatId);

    if (await member(chatId, socket.user.id)) {
      socket.join("chat:" + chatId);
    }
  });

  socket.on("sendMessage", async (data, callback) => {
    try {
      const chatId = Number(data?.chatId);
      const text = String(data?.text || "")
        .trim()
        .slice(0, 2000);

      if (!text) {
        return callback?.({
          ok: false,
          error: "Пустое сообщение"
        });
      }

      if (!(await member(chatId, socket.user.id))) {
        return callback?.({
          ok: false,
          error: "Нет доступа"
        });
      }

      const result = await query(
        `
        INSERT INTO messages(chat_id,sender_id,text)
        VALUES($1,$2,$3)
        RETURNING id,chat_id,sender_id,text,created_at
        `,
        [chatId, socket.user.id, text]
      );

      const message = {
        ...result.rows[0],
        sender_username: socket.user.username
      };

      io.to("chat:" + chatId).emit(
        "newMessage",
        message
      );

      callback?.({ ok: true });
    } catch (e) {
      console.error(e);

      callback?.({
        ok: false,
        error: "Ошибка отправки"
      });
    }
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

async function start() {
  try {
    await initDB();

    server.listen(PORT, "0.0.0.0", () => {
      console.log(
        "M-Talk running on port " + PORT
      );
    });
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

start();
