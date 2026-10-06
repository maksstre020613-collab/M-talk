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

if (!JWT_SECRET || !DATABASE_URL) {
  console.error("JWT_SECRET or DATABASE_URL is missing");
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

async function db(sql, params = []) {
  return pool.query(sql, params);
}

async function initDB() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_seen TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS display_name TEXT
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT NOW()
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY(chat_id,user_id)
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      reply_to_id BIGINT REFERENCES messages(id) ON DELETE SET NULL,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS reply_to_id BIGINT
  `);

  await db(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ
  `);

  await db(`
    CREATE INDEX IF NOT EXISTS messages_chat_idx
    ON messages(chat_id,id)
  `);

  await db(`
    CREATE INDEX IF NOT EXISTS members_user_idx
    ON chat_members(user_id)
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
  const h = req.headers.authorization || "";

  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Необходима авторизация"
    });
  }

  try {
    req.user = jwt.verify(
      h.slice(7),
      JWT_SECRET
    );

    next();
  } catch {
    res.status(401).json({
      error: "Недействительный токен"
    });
  }
}

async function isMember(chatId, userId) {
  const r = await db(
    `
    SELECT 1
    FROM chat_members
    WHERE chat_id=$1 AND user_id=$2
    `,
    [chatId, userId]
  );

  return r.rowCount > 0;
}

const online = new Map();

function setOnline(userId, socketId) {
  if (!online.has(userId)) {
    online.set(userId, new Set());
  }

  online.get(userId).add(socketId);

  io.emit("userStatus", {
    userId,
    online: true
  });
}

async function setOffline(userId, socketId) {
  const sockets = online.get(userId);

  if (sockets) {
    sockets.delete(socketId);

    if (sockets.size === 0) {
      online.delete(userId);

      await db(
        "UPDATE users SET last_seen=NOW() WHERE id=$1",
        [userId]
      );

      io.emit("userStatus", {
        userId,
        online: false,
        lastSeen: new Date().toISOString()
      });
    }
  }
}

/* REGISTER */

app.post("/api/register", async (req, res) => {
  try {
    const username =
      String(req.body.username || "").trim();

    const displayName =
      String(req.body.displayName || username)
        .trim()
        .slice(0, 30);

    const password =
      String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Ник: 3–20 символов, буквы, цифры и _"
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        error: "Пароль минимум 4 символа"
      });
    }

    const exists = await db(
      `
      SELECT id
      FROM users
      WHERE LOWER(username)=LOWER($1)
      `,
      [username]
    );

    if (exists.rowCount) {
      return res.status(409).json({
        error: "Такой ник уже занят"
      });
    }

    const hash =
      await bcrypt.hash(password, 10);

    const r = await db(
      `
      INSERT INTO users(
        username,
        display_name,
        password_hash
      )
      VALUES($1,$2,$3)
      RETURNING id,username,display_name
      `,
      [
        username,
        displayName || username,
        hash
      ]
    );

    const user = r.rows[0];

    res.json({
      token: makeToken(user),
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
    const username =
      String(req.body.username || "").trim();

    const password =
      String(req.body.password || "");

    const r = await db(
      `
      SELECT
        id,
        username,
        display_name,
        password_hash
      FROM users
      WHERE LOWER(username)=LOWER($1)
      `,
      [username]
    );

    if (!r.rowCount) {
      return res.status(401).json({
        error: "Неверный логин или пароль"
      });
    }

    const user = r.rows[0];

    if (
      !(await bcrypt.compare(
        password,
        user.password_hash
      ))
    ) {
      return res.status(401).json({
        error: "Неверный логин или пароль"
      });
    }

    res.json({
      token: makeToken(user),
      user: {
        id: user.id,
        username: user.username,
        display_name:
          user.display_name || user.username
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
  const r = await db(
    `
    SELECT
      id,
      username,
      COALESCE(display_name,username)
      AS display_name,
      created_at,
      last_seen
    FROM users
    WHERE id=$1
    `,
    [req.user.id]
  );

  if (!r.rowCount) {
    return res.status(404).json({
      error: "Пользователь не найден"
    });
  }

  res.json(r.rows[0]);
});

/* CHANGE DISPLAY NAME */

app.patch("/api/me", auth, async (req, res) => {
  const name =
    String(req.body.displayName || "")
      .trim()
      .slice(0, 30);

  if (!name) {
    return res.status(400).json({
      error: "Имя не может быть пустым"
    });
  }

  const r = await db(
    `
    UPDATE users
    SET display_name=$1
    WHERE id=$2
    RETURNING id,username,display_name
    `,
    [name, req.user.id]
  );

  res.json(r.rows[0]);
});

/* SEARCH */

app.get("/api/users", auth, async (req, res) => {
  const q =
    String(req.query.q || "").trim();

  if (!q) return res.json([]);

  const r = await db(
    `
    SELECT
      id,
      username,
      COALESCE(display_name,username)
      AS display_name,
      last_seen
    FROM users
    WHERE id<>$1
      AND (
        display_name ILIKE $2
        OR username ILIKE $2
      )
    ORDER BY display_name
    LIMIT 30
    `,
    [req.user.id, `%${q}%`]
  );

  res.json(
    r.rows.map(x => ({
      ...x,
      online: online.has(x.id)
    }))
  );
});

/* CREATE CHAT */

app.post("/api/chats", auth, async (req, res) => {
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

  const user = await db(
    `
    SELECT
      id,
      username,
      COALESCE(display_name,username)
      AS display_name,
      last_seen
    FROM users
    WHERE id=$1
    `,
    [otherId]
  );

  if (!user.rowCount) {
    return res.status(404).json({
      error: "Пользователь не найден"
    });
  }

  const existing = await db(
    `
    SELECT c.id
    FROM chats c
    JOIN chat_members a
      ON a.chat_id=c.id
    JOIN chat_members b
      ON b.chat_id=c.id
    WHERE a.user_id=$1
      AND b.user_id=$2
    LIMIT 1
    `,
    [req.user.id, otherId]
  );

  if (existing.rowCount) {
    return res.json({
      id: existing.rows[0].id,
      user: user.rows[0]
    });
  }

  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    const chat =
      await client.query(
        "INSERT INTO chats DEFAULT VALUES RETURNING id"
      );

    const chatId =
      chat.rows[0].id;

    await client.query(
      `
      INSERT INTO chat_members(
        chat_id,user_id
      )
      VALUES($1,$2),($1,$3)
      `,
      [
        chatId,
        req.user.id,
        otherId
      ]
    );

    await client.query("COMMIT");

    res.json({
      id: chatId,
      user: user.rows[0]
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
  const r = await db(
    `
    SELECT
      c.id,
      u.id AS user_id,
      u.username,
      COALESCE(
        u.display_name,
        u.username
      ) AS display_name,
      u.last_seen,
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

    ORDER BY
      COALESCE(
        lm.created_at,
        c.created_at
      ) DESC
    `,
    [req.user.id]
  );

  res.json(
    r.rows.map(x => ({
      ...x,
      online: online.has(x.user_id)
    }))
  );
});

/* MESSAGES */

app.get(
  "/api/chats/:id/messages",
  auth,
  async (req, res) => {
    const chatId =
      Number(req.params.id);

    if (
      !(await isMember(
        chatId,
        req.user.id
      ))
    ) {
      return res.status(403).json({
        error: "Нет доступа"
      });
    }

    const r = await db(
      `
      SELECT
        m.id,
        m.chat_id,
        m.sender_id,
        u.username AS sender_username,
        COALESCE(
          u.display_name,
          u.username
        ) AS sender_display_name,
        m.text,
        m.read_at,
        m.created_at,

        rm.text AS reply_text,
        ru.username AS reply_username,
        COALESCE(
          ru.display_name,
          ru.username
        ) AS reply_display_name

      FROM messages m

      JOIN users u
        ON u.id=m.sender_id

      LEFT JOIN messages rm
        ON rm.id=m.reply_to_id

      LEFT JOIN users ru
        ON ru.id=rm.sender_id

      WHERE m.chat_id=$1
      ORDER BY m.id ASC
      LIMIT 300
      `,
      [chatId]
    );

    res.json(r.rows);
  }
);

/* READ */

app.post(
  "/api/chats/:id/read",
  auth,
  async (req, res) => {
    const chatId =
      Number(req.params.id);

    if (
      !(await isMember(
        chatId,
        req.user.id
      ))
    ) {
      return res.status(403).json({
        error: "Нет доступа"
      });
    }

    await db(
      `
      UPDATE messages
      SET read_at=NOW()
      WHERE chat_id=$1
        AND sender_id<>$2
        AND read_at IS NULL
      `,
      [
        chatId,
        req.user.id
      ]
    );

    const members =
      await db(
        `
        SELECT user_id
        FROM chat_members
        WHERE chat_id=$1
        `,
        [chatId]
      );

    for (const m of members.rows) {
      io.to(
        "user:" + m.user_id
      ).emit(
        "messagesRead",
        {
          chatId,
          userId: req.user.id
        }
      );
    }

    res.json({ ok: true });
  }
);

/* SOCKET */

io.use((socket, next) => {
  try {
    socket.user =
      jwt.verify(
        socket.handshake.auth?.token,
        JWT_SECRET
      );

    next();
  } catch {
    next(
      new Error(
        "Авторизация не пройдена"
      )
    );
  }
});

io.on("connection", socket => {
  const userId =
    socket.user.id;

  socket.join(
    "user:" + userId
  );

  setOnline(
    userId,
    socket.id
  );

  socket.on(
    "joinChat",
    async chatId => {
      chatId = Number(chatId);

      if (
        await isMember(
          chatId,
          userId
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
    async (data, callback) => {
      try {
        const chatId =
          Number(data?.chatId);

        const text =
          String(data?.text || "")
            .trim()
            .slice(0, 2000);

        const replyTo =
          data?.replyTo
            ? Number(data.replyTo)
            : null;

        if (!text) {
          return callback?.({
            ok: false,
            error: "Пустое сообщение"
          });
        }

        if (
          !(await isMember(
            chatId,
            userId
          ))
        ) {
          return callback?.({
            ok: false,
            error: "Нет доступа"
          });
        }

        const r = await db(
          `
          INSERT INTO messages(
            chat_id,
            sender_id,
            text,
            reply_to_id
          )
          VALUES($1,$2,$3,$4)
          RETURNING
            id,
            chat_id,
            sender_id,
            text,
            reply_to_id,
            read_at,
            created_at
          `,
          [
            chatId,
            userId,
            text,
            replyTo
          ]
        );

        const msg = r.rows[0];

        if (replyTo) {
          const reply =
            await db(
              `
              SELECT
                m.text,
                u.username,
                COALESCE(
                  u.display_name,
                  u.username
                ) AS display_name
              FROM messages m
              JOIN users u
                ON u.id=m.sender_id
              WHERE m.id=$1
              `,
              [replyTo]
            );

          if (reply.rowCount) {
            msg.reply_text =
              reply.rows[0].text;

            msg.reply_username =
              reply.rows[0].username;

            msg.reply_display_name =
              reply.rows[0].display_name;
          }
        }

        msg.sender_username =
          socket.user.username;

        io.to(
          "chat:" + chatId
        ).emit(
          "newMessage",
          msg
        );

        callback?.({
          ok: true
        });
      } catch (e) {
        console.error(e);

        callback?.({
          ok: false,
          error: "Ошибка отправки"
        });
      }
    }
  );

  socket.on(
    "disconnect",
    () => {
      setOffline(
        userId,
        socket.id
      ).catch(console.error);
    }
  );
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "M-Talk"
  });
});

async function start() {
  try {
    await initDB();

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
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

start();
