const express = require("express");
const http = require("http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const { Server } = require("socket.io");
const { firebase } = require("./firebase");

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
  ssl: {
    rejectUnauthorized: false
  }
});

/* =========================
   SECURITY
========================= */

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'", "ws:", "wss:"],
        imgSrc: ["'self'", "data:", "blob:"],
        mediaSrc: ["'self'", "data:", "blob:"],
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

app.use(express.static("public"));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/register", limiter);
app.use("/api/login", limiter);

/* =========================
   DATABASE
========================= */

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
      chat_id INTEGER
        REFERENCES chats(id)
        ON DELETE CASCADE,

      user_id INTEGER
        REFERENCES users(id)
        ON DELETE CASCADE,

      PRIMARY KEY(chat_id, user_id)
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,

      chat_id INTEGER
        REFERENCES chats(id)
        ON DELETE CASCADE,

      sender_id INTEGER
        REFERENCES users(id)
        ON DELETE CASCADE,

      text TEXT NOT NULL,

      reply_to_id BIGINT
        REFERENCES messages(id)
        ON DELETE SET NULL,

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
    ON messages(chat_id, id)
  `);

  await db(`
    CREATE INDEX IF NOT EXISTS members_user_idx
    ON chat_members(user_id)
  `);

  /* =========================
     FCM TOKENS
  ========================= */

  await db(`
    CREATE TABLE IF NOT EXISTS push_tokens (
      id BIGSERIAL PRIMARY KEY,

      user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      token TEXT NOT NULL UNIQUE,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  await db(`
    CREATE INDEX IF NOT EXISTS idx_push_tokens_user
    ON push_tokens(user_id)
  `);

  console.log("PostgreSQL database ready");
}

/* =========================
   HELPERS
========================= */

function avatarLetter(name, username) {
  const value = String(
    name ||
    username ||
    "?"
  ).trim();

  if (!value) {
    return "?";
  }

  return value
    .charAt(0)
    .toUpperCase();
}

function makeUser(user) {
  const displayName =
    user.display_name ||
    user.username;

  return {
    id: user.id,
    username: user.username,
    display_name: displayName,
    avatar: avatarLetter(
      displayName,
      user.username
    ),
    last_seen: user.last_seen || null
  };
}

function makeToken(user) {
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

function auth(req, res, next) {
  const h =
    req.headers.authorization || "";

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
    return res.status(401).json({
      error: "Недействительный токен"
    });
  }
}

async function isMember(chatId, userId) {
  const r = await db(
    `
    SELECT 1
    FROM chat_members
    WHERE chat_id=$1
      AND user_id=$2
    `,
    [
      chatId,
      userId
    ]
  );

  return r.rowCount > 0;
}

/* =========================
   FCM
========================= */

async function sendPushToUser(
  userId,
  title,
  body,
  chatId
) {
  const admin = firebase();

  if (!admin) {
    return;
  }

  try {
    const result = await db(
      `
      SELECT token
      FROM push_tokens
      WHERE user_id=$1
      `,
      [userId]
    );

    const tokens =
      result.rows.map(
        row => row.token
      );

    if (!tokens.length) {
      return;
    }

    const response =
      await admin.messaging()
        .sendEachForMulticast({
          tokens,

          data: {
            title: String(title),
            body: String(body),
            chatId: String(chatId)
          },

          android: {
            priority: "high"
          }
        });

    const invalidTokens = [];

    response.responses.forEach(
      (item, index) => {
        if (!item.success) {
          const code =
            item.error?.code || "";

          if (
            code.includes(
              "registration-token-not-registered"
            ) ||
            code.includes(
              "invalid-registration-token"
            )
          ) {
            invalidTokens.push(
              tokens[index]
            );
          }
        }
      }
    );

    if (invalidTokens.length) {
      await db(
        `
        DELETE FROM push_tokens
        WHERE token = ANY($1::text[])
        `,
        [invalidTokens]
      );
    }

  } catch (error) {
    console.error(
      "FCM send error:",
      error
    );
  }
}

/* =========================
   ONLINE
========================= */

const online = new Map();

function setOnline(
  userId,
  socketId
) {
  if (!online.has(userId)) {
    online.set(
      userId,
      new Set()
    );
  }

  online
    .get(userId)
    .add(socketId);

  io.emit(
    "userStatus",
    {
      userId,
      online: true
    }
  );
}

async function setOffline(
  userId,
  socketId
) {
  const sockets =
    online.get(userId);

  if (!sockets) {
    return;
  }

  sockets.delete(socketId);

  if (sockets.size === 0) {
    online.delete(userId);

    const now =
      new Date().toISOString();

    await db(
      `
      UPDATE users
      SET last_seen=NOW()
      WHERE id=$1
      `,
      [userId]
    );

    io.emit(
      "userStatus",
      {
        userId,
        online: false,
        lastSeen: now
      }
    );
  }
}

/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ""
        ).trim();

      const displayName =
        String(
          req.body.displayName ||
          username
        )
          .trim()
          .slice(0, 30);

      const password =
        String(
          req.body.password || ""
        );

      if (
        !/^[a-zA-Z0-9_]{3,20}$/
          .test(username)
      ) {
        return res.status(400).json({
          error:
            "Ник: 3–20 символов, буквы, цифры и _"
        });
      }

      if (password.length < 4) {
        return res.status(400).json({
          error:
            "Пароль минимум 4 символа"
        });
      }

      const exists =
        await db(
          `
          SELECT id
          FROM users
          WHERE LOWER(username)
            = LOWER($1)
          `,
          [username]
        );

      if (exists.rowCount) {
        return res.status(409).json({
          error:
            "Такой ник уже занят"
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          10
        );

      const r =
        await db(
          `
          INSERT INTO users(
            username,
            display_name,
            password_hash
          )
          VALUES($1,$2,$3)

          RETURNING
            id,
            username,
            display_name,
            last_seen
          `,
          [
            username,
            displayName || username,
            hash
          ]
        );

      const user =
        makeUser(r.rows[0]);

      return res.json({
        token:
          makeToken(r.rows[0]),
        user
      });

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   PUSH TOKEN
========================= */

app.post(
  "/api/push-token",
  auth,
  async (req, res) => {
    const token =
      String(
        req.body.token || ""
      ).trim();

    if (
      !token ||
      token.length > 4096
    ) {
      return res.status(400).json({
        error:
          "Неверный FCM токен"
      });
    }

    try {
      await db(
        `
        INSERT INTO push_tokens(
          user_id,
          token,
          updated_at
        )
        VALUES(
          $1,
          $2,
          NOW()
        )

        ON CONFLICT (token)

        DO UPDATE SET
          user_id=EXCLUDED.user_id,
          updated_at=NOW()
        `,
        [
          req.user.id,
          token
        ]
      );

      return res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        "FCM token save error:",
        error
      );

      return res.status(500).json({
        error:
          "Не удалось сохранить токен"
      });
    }
  }
);

/* =========================
   DELETE PUSH TOKEN
========================= */

app.delete(
  "/api/push-token",
  auth,
  async (req, res) => {
    const token =
      String(
        req.body.token || ""
      ).trim();

    if (!token) {
      return res.status(400).json({
        error:
          "Токен не указан"
      });
    }

    try {
      await db(
        `
        DELETE FROM push_tokens

        WHERE user_id=$1
          AND token=$2
        `,
        [
          req.user.id,
          token
        ]
      );

      return res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        "FCM token delete error:",
        error
      );

      return res.status(500).json({
        error:
          "Не удалось удалить токен"
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      const r =
        await db(
          `
          SELECT
            id,
            username,
            display_name,
            password_hash,
            last_seen

          FROM users

          WHERE LOWER(username)
            = LOWER($1)
          `,
          [username]
        );

      if (!r.rowCount) {
        return res.status(401).json({
          error:
            "Неверный логин или пароль"
        });
      }

      const user =
        r.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Неверный логин или пароль"
        });
      }

      const safeUser =
        makeUser(user);

      return res.json({
        token:
          makeToken(user),

        user:
          safeUser
      });

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   ME
========================= */

app.get(
  "/api/me",
  auth,
  async (req, res) => {
    try {
      const r =
        await db(
          `
          SELECT
            id,
            username,

            COALESCE(
              display_name,
              username
            ) AS display_name,

            created_at,
            last_seen

          FROM users

          WHERE id=$1
          `,
          [req.user.id]
        );

      if (!r.rowCount) {
        return res.status(404).json({
          error:
            "Пользователь не найден"
        });
      }

      const user =
        makeUser(r.rows[0]);

      user.created_at =
        r.rows[0].created_at;

      return res.json(user);

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   CHANGE DISPLAY NAME
========================= */

app.patch(
  "/api/me",
  auth,
  async (req, res) => {
    try {
      const name =
        String(
          req.body.displayName || ""
        )
          .trim()
          .slice(0, 30);

      if (!name) {
        return res.status(400).json({
          error:
            "Имя не может быть пустым"
        });
      }

      const r =
        await db(
          `
          UPDATE users

          SET display_name=$1

          WHERE id=$2

          RETURNING
            id,
            username,
            display_name,
            last_seen
          `,
          [
            name,
            req.user.id
          ]
        );

      if (!r.rowCount) {
        return res.status(404).json({
          error:
            "Пользователь не найден"
        });
      }

      return res.json(
        makeUser(r.rows[0])
      );

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   SEARCH USERS
========================= */

app.get(
  [
    "/api/users",
    "/api/users/search"
  ],
  auth,
  async (req, res) => {
    try {
      const q =
        String(
          req.query.q || ""
        ).trim();

      if (!q) {
        return res.json([]);
      }

      const r =
        await db(
          `
          SELECT
            id,
            username,

            COALESCE(
              display_name,
              username
            ) AS display_name,

            last_seen

          FROM users

          WHERE id<>$1

            AND (
              display_name
                ILIKE $2

              OR username
                ILIKE $2
            )

          ORDER BY display_name

          LIMIT 30
          `,
          [
            req.user.id,
            `%${q}%`
          ]
        );

      return res.json(
        r.rows.map(
          user => ({
            ...makeUser(user),

            online:
              online.has(user.id)
          })
        )
      );

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   CREATE CHAT
========================= */

app.post(
  "/api/chats",
  auth,
  async (req, res) => {
    try {
      const otherId =
        Number(req.body.userId);

      if (
        !Number.isInteger(otherId) ||
        otherId === req.user.id
      ) {
        return res.status(400).json({
          error:
            "Неверный пользователь"
        });
      }

      const user =
        await db(
          `
          SELECT
            id,
            username,

            COALESCE(
              display_name,
              username
            ) AS display_name,

            last_seen

          FROM users

          WHERE id=$1
          `,
          [otherId]
        );

      if (!user.rowCount) {
        return res.status(404).json({
          error:
            "Пользователь не найден"
        });
      }

      const existing =
        await db(
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
          [
            req.user.id,
            otherId
          ]
        );

      const otherUser =
        makeUser(
          user.rows[0]
        );

      if (existing.rowCount) {
        return res.json({
          id:
            existing.rows[0].id,

          user:
            otherUser
        });
      }

      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

        const chat =
          await client.query(
            `
            INSERT INTO chats
            DEFAULT VALUES

            RETURNING id
            `
          );

        const chatId =
          chat.rows[0].id;

        await client.query(
          `
          INSERT INTO chat_members(
            chat_id,
            user_id
          )

          VALUES
            ($1,$2),
            ($1,$3)
          `,
          [
            chatId,
            req.user.id,
            otherId
          ]
        );

        await client.query(
          "COMMIT"
        );

        return res.json({
          id: chatId,
          user: otherUser
        });

      } catch (e) {
        await client.query(
          "ROLLBACK"
        );

        throw e;

      } finally {
        client.release();
      }

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   CHAT LIST
========================= */

app.get(
  "/api/chats",
  auth,
  async (req, res) => {
    try {
      const r =
        await db(
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

            lm.text
              AS last_message,

            lm.created_at
              AS last_message_at

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
            SELECT
              text,
              created_at

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

      return res.json(
        r.rows.map(x => ({
          id: x.id,

          user_id:
            x.user_id,

          username:
            x.username,

          display_name:
            x.display_name,

          avatar:
            avatarLetter(
              x.display_name,
              x.username
            ),

          last_seen:
            x.last_seen,

          last_message:
            x.last_message,

          last_message_at:
            x.last_message_at,

          online:
            online.has(
              x.user_id
            )
        }))
      );

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   GET MESSAGES
========================= */

app.get(
  "/api/chats/:id/messages",
  auth,
  async (req, res) => {
    try {
      const chatId =
        Number(req.params.id);

      if (
        !(await isMember(
          chatId,
          req.user.id
        ))
      ) {
        return res.status(403).json({
          error:
            "Нет доступа"
        });
      }

      const r =
        await db(
          `
          SELECT

            m.id,

            m.chat_id,

            m.sender_id,

            u.username
              AS sender_username,

            COALESCE(
              u.display_name,
              u.username
            ) AS sender_display_name,

            m.text,

            m.reply_to_id,

            m.read_at,

            m.created_at,

            rm.text
              AS reply_text,

            ru.username
              AS reply_username,

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

      return res.json(
        r.rows.map(message => ({
          ...message,

          sender_avatar:
            avatarLetter(
              message.sender_display_name,
              message.sender_username
            ),

          reply_avatar:
            message.reply_display_name
              ? avatarLetter(
                  message.reply_display_name,
                  message.reply_username
                )
              : null
        }))
      );

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   MARK READ
========================= */

app.post(
  "/api/chats/:id/read",
  auth,
  async (req, res) => {
    try {
      const chatId =
        Number(req.params.id);

      if (
        !(await isMember(
          chatId,
          req.user.id
        ))
      ) {
        return res.status(403).json({
          error:
            "Нет доступа"
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

      for (
        const member
        of members.rows
      ) {
        io.to(
          "user:" +
          member.user_id
        ).emit(
          "messagesRead",
          {
            chatId,
            userId:
              req.user.id
          }
        );
      }

      return res.json({
        ok: true
      });

    } catch (e) {
      console.error(e);

      return res.status(500).json({
        error:
          "Ошибка сервера"
      });
    }
  }
);

/* =========================
   SOCKET AUTH
========================= */

io.use(
  (socket, next) => {
    try {
      const token =
        socket.handshake
          .auth?.token;

      socket.user =
        jwt.verify(
          token,
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
  }
);

/* =========================
   SOCKET CONNECTION
========================= */

io.on(
  "connection",
  socket => {
    const userId =
      socket.user.id;

    socket.join(
      "user:" + userId
    );

    setOnline(
      userId,
      socket.id
    );

    /* JOIN CHAT */

    socket.on(
      "joinChat",
      async chatId => {
        try {
          chatId =
            Number(chatId);

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

        } catch (e) {
          console.error(e);
        }
      }
    );

    /* SEND MESSAGE */

    socket.on(
      "sendMessage",
      async (
        data,
        callback
      ) => {
        try {
          const chatId =
            Number(
              data?.chatId
            );

          const text =
            String(
              data?.text || ""
            )
              .trim()
              .slice(0, 2000);

          const replyTo =
            data?.replyTo
              ? Number(
                  data.replyTo
                )
              : null;

          if (!text) {
            return callback?.({
              ok: false,
              error:
                "Пустое сообщение"
            });
          }

          if (
            !Number.isInteger(
              chatId
            )
          ) {
            return callback?.({
              ok: false,
              error:
                "Неверный чат"
            });
          }

          if (
            replyTo !== null &&
            !Number.isInteger(
              replyTo
            )
          ) {
            return callback?.({
              ok: false,
              error:
                "Неверный ответ"
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
              error:
                "Нет доступа"
            });
          }

          if (replyTo) {
            const replyExists =
              await db(
                `
                SELECT id

                FROM messages

                WHERE id=$1
                  AND chat_id=$2
                `,
                [
                  replyTo,
                  chatId
                ]
              );

            if (!replyExists.rowCount) {
              return callback?.({
                ok: false,
                error:
                  "Сообщение для ответа не найдено"
              });
            }
          }

          const r =
            await db(
              `
              INSERT INTO messages(
                chat_id,
                sender_id,
                text,
                reply_to_id
              )

              VALUES(
                $1,
                $2,
                $3,
                $4
              )

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

          const msg =
            r.rows[0];

          const sender =
            await db(
              `
              SELECT
                username,

                COALESCE(
                  display_name,
                  username
                ) AS display_name

              FROM users

              WHERE id=$1
              `,
              [userId]
            );

          if (sender.rowCount) {
            msg.sender_username =
              sender.rows[0]
                .username;

            msg.sender_display_name =
              sender.rows[0]
                .display_name;

            msg.sender_avatar =
              avatarLetter(
                sender.rows[0]
                  .display_name,

                sender.rows[0]
                  .username
              );
          }

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
                reply.rows[0]
                  .text;

              msg.reply_username =
                reply.rows[0]
                  .username;

              msg.reply_display_name =
                reply.rows[0]
                  .display_name;

              msg.reply_avatar =
                avatarLetter(
                  reply.rows[0]
                    .display_name,

                  reply.rows[0]
                    .username
                );
            }
          }

          /* =========================
             SEND TO CHAT
          ========================= */

          io.to(
            "chat:" + chatId
          ).emit(
            "newMessage",
            msg
          );

          /* =========================
             FIND OTHER USERS
          ========================= */

          const members =
            await db(
              `
              SELECT
                user_id

              FROM chat_members

              WHERE chat_id=$1
                AND user_id<>$2
              `,
              [
                chatId,
                userId
              ]
            );

          /* =========================
             SEND FCM
          ========================= */

          for (
            const member
            of members.rows
          ) {
            await sendPushToUser(
              member.user_id,

              msg.sender_display_name ||
                msg.sender_username ||
                "Новое сообщение",

              msg.text,

              chatId
            );
          }

          /* =========================
             ACK
          ========================= */

          callback?.({
            ok: true,
            message: msg
          });

        } catch (e) {
          console.error(e);

          callback?.({
            ok: false,
            error:
              "Ошибка отправки"
          });
        }
      }
    );

    /* DISCONNECT */

    socket.on(
      "disconnect",
      () => {
        setOffline(
          userId,
          socket.id
        ).catch(
          console.error
        );
      }
    );
  }
);

/* =========================
   HEALTH
========================= */

app.get(
  "/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "M-Talk"
    });
  }
);

/* =========================
   START
========================= */

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
