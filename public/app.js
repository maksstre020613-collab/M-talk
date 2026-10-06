let token = localStorage.getItem("mtalk_token");
let me = null;
let socket = null;
let currentChat = null;
let replyTo = null;
let touchStartX = 0;
let currentMessages = [];

const $ = id => document.getElementById(id);

async function api(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = "Bearer " + token;
  }

  const r = await fetch(url, {
    ...options,
    headers
  });

  const data = await r.json().catch(() => ({}));

  if (!r.ok) {
    throw new Error(data.error || "Ошибка");
  }

  return data;
}

/* AUTH */

$("showLogin").onclick = () => {
  $("registerBox").hidden = true;
  $("loginBox").hidden = false;
};

$("showRegister").onclick = () => {
  $("loginBox").hidden = true;
  $("registerBox").hidden = false;
};

$("registerBtn").onclick = async () => {
  try {
    $("authError").textContent = "";

    const data = await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        displayName: $("regName").value,
        username: $("regUser").value,
        password: $("regPass").value
      })
    });

    token = data.token;
    localStorage.setItem("mtalk_token", token);

    await startApp();
  } catch (e) {
    $("authError").textContent = e.message;
  }
};

$("loginBtn").onclick = async () => {
  try {
    $("authError").textContent = "";

    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("loginUser").value,
        password: $("loginPass").value
      })
    });

    token = data.token;
    localStorage.setItem("mtalk_token", token);

    await startApp();
  } catch (e) {
    $("authError").textContent = e.message;
  }
};

/* APP */

async function startApp() {
  try {
    me = await api("/api/me");

    $("auth").hidden = true;
    $("app").hidden = false;

    applyTheme();
    connectSocket();
    loadChats();

    $("topTitle").textContent =
      me.display_name || me.username;

    $("topStatus").textContent =
      "в сети";

  } catch {
    logout();
  }
}

function connectSocket() {
  socket = io({
    auth: {
      token
    }
  });

  socket.on("newMessage", msg => {
    if (
      currentChat &&
      Number(msg.chat_id) === Number(currentChat.id)
    ) {
      currentMessages.push(msg);
      renderMessages();
      scrollBottom();

      markRead();
    }

    loadChats();
  });

  socket.on("messagesRead", data => {
    if (
      currentChat &&
      Number(data.chatId) ===
      Number(currentChat.id)
    ) {
      loadMessages(false);
    }
  });

  socket.on("userStatus", data => {
    updateOnlineStatus(
      data.userId,
      data.online
    );

    if (
      currentChat &&
      Number(currentChat.user_id) ===
      Number(data.userId)
    ) {
      $("topStatus").textContent =
        data.online
          ? "в сети"
          : "был(а) недавно";
    }
  });
}

/* CHATS */

async function loadChats() {
  try {
    const chats = await api("/api/chats");

    $("chatList").innerHTML = "";

    if (!chats.length) {
      $("chatList").innerHTML = `
        <div style="padding:40px;text-align:center;color:#8d9aa7">
          🔎 Найдите человека через поиск<br>
          и начните общение
        </div>
      `;
      return;
    }

    chats.forEach(chat => {
      const item = document.createElement("div");
      item.className = "chatItem";

      const letter =
        (chat.display_name ||
          chat.username)[0].toUpperCase();

      item.innerHTML = `
        <div class="avatar">${escapeHtml(letter)}</div>

        <div class="chatInfo">
          <b>
            ${escapeHtml(
              chat.display_name ||
              chat.username
            )}
          </b>

          <span class="${
            chat.online ? "online" : ""
          }">
            ${
              chat.online
                ? "● в сети"
                : escapeHtml(
                    chat.last_message ||
                    "Нет сообщений"
                  )
            }
          </span>
        </div>
      `;

      item.onclick = () =>
        openChat(chat);

      $("chatList").appendChild(item);
    });
  } catch (e) {
    console.error(e);
  }
}

/* SEARCH */

$("searchBtn").onclick = () => {
  $("searchPanel").hidden =
    !$("searchPanel").hidden;

  if (!$("searchPanel").hidden) {
    $("searchInput").focus();
  }
};

let searchTimer;

$("searchInput").oninput = () => {
  clearTimeout(searchTimer);

  searchTimer = setTimeout(
    searchUsers,
    250
  );
};

async function searchUsers() {
  const q =
    $("searchInput").value.trim();

  if (!q) {
    $("searchResults").innerHTML = "";
    return;
  }

  try {
    const users =
      await api(
        "/api/users?q=" +
        encodeURIComponent(q)
      );

    $("searchResults").innerHTML = "";

    if (!users.length) {
      $("searchResults").innerHTML =
        `<div style="padding:18px;color:#8d9aa7">
          Никого не найдено
        </div>`;

      return;
    }

    users.forEach(user => {
      const item =
        document.createElement("div");

      item.className = "userResult";

      item.innerHTML = `
        <div class="avatar">
          ${escapeHtml(
            (user.display_name ||
              user.username)[0]
              .toUpperCase()
          )}
        </div>

        <div class="userInfo">
          <b>
            ${escapeHtml(
              user.display_name ||
              user.username
            )}
          </b>

          <span class="${
            user.online ? "online" : ""
          }">
            ${
              user.online
                ? "● в сети"
                : "@" +
                  escapeHtml(
                    user.username
                  )
            }
          </span>
        </div>
      `;

      item.onclick = () =>
        startChat(user);

      $("searchResults").appendChild(item);
    });
  } catch (e) {
    console.error(e);
  }
}

async function startChat(user) {
  try {
    const chat =
      await api("/api/chats", {
        method: "POST",
        body: JSON.stringify({
          userId: user.id
        })
      });

    openChat({
      ...chat,
      user_id: user.id,
      username: user.username,
      display_name:
        user.display_name,
      online: user.online
    });

    $("searchPanel").hidden = true;
    $("searchInput").value = "";
    $("searchResults").innerHTML = "";
  } catch (e) {
    alert(e.message);
  }
}

/* OPEN CHAT */

async function openChat(chat) {
  currentChat = chat;

  $("chatList").hidden = true;
  $("chat").hidden = false;
  $("backBtn").hidden = false;

  $("topTitle").textContent =
    chat.display_name ||
    chat.username;

  $("topStatus").textContent =
    chat.online
      ? "в сети"
      : "был(а) недавно";

  socket.emit(
    "joinChat",
    chat.id
  );

  await loadMessages();

  markRead();
}

$("backBtn").onclick = () => {
  currentChat = null;

  $("chat").hidden = true;
  $("chatList").hidden = false;
  $("backBtn").hidden = true;

  $("topTitle").textContent =
    me.display_name || me.username;

  $("topStatus").textContent =
    "в сети";

  loadChats();
};

/* MESSAGES */

async function loadMessages(scroll = true) {
  if (!currentChat) return;

  try {
    currentMessages =
      await api(
        `/api/chats/${currentChat.id}/messages`
      );

    renderMessages();

    if (scroll) {
      scrollBottom();
    }
  } catch (e) {
    console.error(e);
  }
}

function renderMessages() {
  $("messages").innerHTML = "";

  currentMessages.forEach(msg => {
    const el =
      document.createElement("div");

    el.className =
      "message " +
      (
        Number(msg.sender_id) ===
        Number(me.id)
          ? "mine"
          : "other"
      );

    const date =
      new Date(
        msg.created_at
      ).toLocaleTimeString(
        "ru-RU",
        {
          hour: "2-digit",
          minute: "2-digit"
        }
      );

    let reply = "";

    if (msg.reply_text) {
      reply = `
        <div class="replyPreview">
          <b>
            ${escapeHtml(
              msg.reply_display_name ||
              msg.reply_username ||
              ""
            )}
          </b>

          ${escapeHtml(
            msg.reply_text
          )}
        </div>
      `;
    }

    const read =
      Number(msg.sender_id) ===
      Number(me.id)
        ? `
          <span class="check">
            ${msg.read_at ? "✓✓" : "✓"}
          </span>
        `
        : "";

    el.innerHTML = `
      ${reply}

      <div class="messageText">
        ${escapeHtml(msg.text)}
      </div>

      <div class="messageMeta">
        ${date}
        ${read}
      </div>
    `;

    addSwipeReply(el, msg);

    $("messages").appendChild(el);
  });
}

/* SEND */

$("sendBtn").onclick = sendMessage;

$("messageInput").onkeydown = e => {
  if (
    e.key === "Enter" &&
    !e.shiftKey
  ) {
    e.preventDefault();
    sendMessage();
  }
};

function sendMessage() {
  const text =
    $("messageInput").value.trim();

  if (!text || !currentChat) return;

  socket.emit(
    "sendMessage",
    {
      chatId: currentChat.id,
      text,
      replyTo:
        replyTo?.id || null
    },
    result => {
      if (!result?.ok) {
        alert(
          result?.error ||
          "Не удалось отправить"
        );

        return;
      }

      $("messageInput").value = "";
      cancelReply();
    }
  );
}

/* READ */

async function markRead() {
  if (!currentChat) return;

  try {
    await api(
      `/api/chats/${currentChat.id}/read`,
      {
        method: "POST"
      }
    );
  } catch {}
}

/* REPLY SWIPE */

function addSwipeReply(el, msg) {
  let start = 0;
  let moved = 0;

  el.addEventListener(
    "touchstart",
    e => {
      start =
        e.touches[0].clientX;

      moved = 0;
    },
    { passive: true }
  );

  el.addEventListener(
    "touchmove",
    e => {
      moved =
        e.touches[0].clientX -
        start;

      if (
        moved > 0 &&
        moved < 80
      ) {
        el.style.transform =
          `translateX(${moved}px)`;
      }
    },
    { passive: true }
  );

  el.addEventListener(
    "touchend",
    () => {
      el.style.transform = "";

      if (moved > 55) {
        setReply(msg);
      }
    }
  );
}

function setReply(msg) {
  replyTo = msg;

  $("replyBox").hidden = false;

  $("replyName").textContent =
    msg.reply_display_name ||
    msg.sender_display_name ||
    msg.sender_username ||
    "Пользователь";

  $("replyText").textContent =
    msg.text;

  $("messageInput").focus();
}

function cancelReply() {
  replyTo = null;
  $("replyBox").hidden = true;
}

$("cancelReply").onclick =
  cancelReply;

/* SETTINGS */

$("settingsBtn").onclick = () => {
  $("settings").hidden = false;

  $("profileName").textContent =
    me.display_name ||
    me.username;

  $("profileUsername").textContent =
    "@" + me.username;

  $("newName").value =
    me.display_name ||
    "";
};

$("closeSettings").onclick = () => {
  $("settings").hidden = true;
};

$("saveName").onclick = async () => {
  try {
    const name =
      $("newName").value.trim();

    const user =
      await api("/api/me", {
        method: "PATCH",
        body: JSON.stringify({
          displayName: name
        })
      });

    me = {
      ...me,
      ...user
    };

    $("profileName").textContent =
      me.display_name;

    $("topTitle").textContent =
      me.display_name;

    $("settings").hidden = true;

    loadChats();
  } catch (e) {
    alert(e.message);
  }
};

/* THEMES */

document
  .querySelectorAll(
    ".themeButtons button"
  )
  .forEach(button => {
    button.onclick = () => {
      const theme =
        button.dataset.theme;

      localStorage.setItem(
        "mtalk_theme",
        theme
      );

      applyTheme();
    };
  });

function applyTheme() {
  const theme =
    localStorage.getItem(
      "mtalk_theme"
    ) || "dark";

  document.body.classList.remove(
    "light",
    "blue"
  );

  if (theme !== "dark") {
    document.body.classList.add(
      theme
    );
  }
}

/* ONLINE */

function updateOnlineStatus(
  userId,
  isOnline
) {
  document
    .querySelectorAll(".userResult")
    .forEach(el => {
      // список поиска обновится при следующем поиске
    });

  if (
    currentChat &&
    Number(currentChat.user_id) ===
    Number(userId)
  ) {
    $("topStatus").textContent =
      isOnline
        ? "в сети"
        : "был(а) недавно";
  }
}

/* LOGOUT */

$("logout").onclick = () => {
  logout();
};

function logout() {
  localStorage.removeItem(
    "mtalk_token"
  );

  token = null;

  if (socket) {
    socket.disconnect();
  }

  location.reload();
}

/* HELPERS */

function scrollBottom() {
  requestAnimationFrame(() => {
    $("messages").scrollTop =
      $("messages").scrollHeight;
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* START */

if (token) {
  startApp();
      }
