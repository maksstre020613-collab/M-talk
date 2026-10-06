let token = localStorage.getItem("mtalk_token");
let me = null;
let socket = null;
let currentChat = null;
let replyTo = null;
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

  const response = await fetch(url, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Ошибка сервера");
  }

  return data;
}

/* =========================
   АВТОРИЗАЦИЯ
========================= */

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
        displayName: $("regName").value.trim(),
        username: $("regUser").value.trim(),
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
        username: $("loginUser").value.trim(),
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

/* =========================
   ЗАПУСК
========================= */

async function startApp() {
  try {
    me = await api("/api/me");

    $("auth").hidden = true;
    $("app").hidden = false;

    updateMyProfile();
    applyTheme();

    connectSocket();
    loadChats();

  } catch (e) {
    console.error(e);
    logout();
  }
}

function updateMyProfile() {
  if (!me) return;

  const name = me.display_name || me.username;

  $("topTitle").textContent = name;
  $("topStatus").textContent = "в сети";

  if ($("profileName")) {
    $("profileName").textContent = name;
  }

  if ($("profileUsername")) {
    $("profileUsername").textContent =
      "@" + me.username;
  }

  if ($("profileAvatar")) {
    $("profileAvatar").textContent =
      getInitials(name);
  }
}

/* =========================
   SOCKET
========================= */

function connectSocket() {
  socket = io({
    auth: {
      token
    }
  });

  socket.on("connect", () => {
    console.log("M-Talk connected");
  });

  socket.on("newMessage", message => {
    if (
      currentChat &&
      Number(message.chat_id) === Number(currentChat.id)
    ) {
      currentMessages.push(message);

      renderMessages();
      scrollBottom();

      if (Number(message.sender_id) !== Number(me.id)) {
        markRead();
      }
    }

    loadChats();
  });

  socket.on("messagesRead", data => {
    if (
      currentChat &&
      Number(data.chatId) === Number(currentChat.id)
    ) {
      loadMessages(false);
    }
  });

  socket.on("userStatus", data => {
    if (
      currentChat &&
      Number(currentChat.user_id) === Number(data.userId)
    ) {
      $("topStatus").textContent =
        data.online ? "● в сети" : "был(а) недавно";

      currentChat.online = data.online;
    }

    loadChats();
  });
}

/* =========================
   ЧАТЫ
========================= */

async function loadChats() {
  try {
    const chats = await api("/api/chats");

    $("chatList").innerHTML = "";

    if (!chats.length) {
      $("chatList").innerHTML = `
        <div class="emptyChats">
          🔎 Найдите человека через поиск<br>
          и начните общение
        </div>
      `;
      return;
    }

    chats.forEach(chat => {
      const item = document.createElement("div");
      item.className = "chatItem";

      const name =
        chat.display_name ||
        chat.username;

      item.innerHTML = `
        <div class="avatar">
          ${escapeHtml(getInitials(name))}
        </div>

        <div class="chatInfo">
          <b>${escapeHtml(name)}</b>

          <span class="${chat.online ? "online" : ""}">
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

      item.onclick = () => openChat(chat);

      $("chatList").appendChild(item);
    });

  } catch (e) {
    console.error(e);
  }
}

/* =========================
   ПОИСК
========================= */

$("searchBtn").onclick = () => {
  $("searchPanel").hidden =
    !$("searchPanel").hidden;

  if (!$("searchPanel").hidden) {
    $("searchInput").focus();
  }
};

let searchTimer = null;

$("searchInput").oninput = () => {
  clearTimeout(searchTimer);

  searchTimer = setTimeout(
    searchUsers,
    250
  );
};

async function searchUsers() {
  const query =
    $("searchInput").value.trim();

  if (!query) {
    $("searchResults").innerHTML = "";
    return;
  }

  try {
    const users = await api(
      "/api/users?q=" +
      encodeURIComponent(query)
    );

    $("searchResults").innerHTML = "";

    if (!users.length) {
      $("searchResults").innerHTML = `
        <div class="noResults">
          Никого не найдено
        </div>
      `;
      return;
    }

    users.forEach(user => {
      const item = document.createElement("div");
      item.className = "userResult";

      const name =
        user.display_name ||
        user.username;

      item.innerHTML = `
        <div class="avatar">
          ${escapeHtml(getInitials(name))}
        </div>

        <div class="userInfo">
          <b>${escapeHtml(name)}</b>

          <span class="${user.online ? "online" : ""}">
            ${
              user.online
                ? "● в сети"
                : "@" + escapeHtml(user.username)
            }
          </span>
        </div>
      `;

      item.onclick = () => startChat(user);

      $("searchResults").appendChild(item);
    });

  } catch (e) {
    console.error(e);
  }
}

/* =========================
   СОЗДАТЬ / ОТКРЫТЬ ЧАТ
========================= */

async function startChat(user) {
  try {
    const chat = await api("/api/chats", {
      method: "POST",
      body: JSON.stringify({
        userId: user.id
      })
    });

    openChat({
      ...chat,
      user_id: user.id,
      username: user.username,
      display_name: user.display_name,
      online: user.online
    });

    $("searchPanel").hidden = true;
    $("searchInput").value = "";
    $("searchResults").innerHTML = "";

  } catch (e) {
    alert(e.message);
  }
}

async function openChat(chat) {
  currentChat = chat;

  $("chatList").hidden = true;
  $("chat").hidden = false;
  $("backBtn").hidden = false;

  const name =
    chat.display_name ||
    chat.username;

  $("topTitle").textContent = name;

  $("topStatus").textContent =
    chat.online
      ? "● в сети"
      : "был(а) недавно";

  socket.emit("joinChat", chat.id);

  await loadMessages();

  markRead();

  setTimeout(() => {
    $("messageInput").focus();
  }, 100);
}

$("backBtn").onclick = () => {
  currentChat = null;
  replyTo = null;

  $("chat").hidden = true;
  $("chatList").hidden = false;
  $("backBtn").hidden = true;

  cancelReply();

  $("topTitle").textContent =
    me.display_name ||
    me.username;

  $("topStatus").textContent = "в сети";

  loadChats();
};

/* =========================
   СООБЩЕНИЯ
========================= */

async function loadMessages(shouldScroll = true) {
  if (!currentChat) return;

  try {
    currentMessages =
      await api(
        `/api/chats/${currentChat.id}/messages`
      );

    renderMessages();

    if (shouldScroll) {
      scrollBottom();
    }

  } catch (e) {
    console.error(e);
  }
}

function renderMessages() {
  $("messages").innerHTML = "";

  currentMessages.forEach(message => {
    const row = document.createElement("div");

    const mine =
      Number(message.sender_id) === Number(me.id);

    row.className =
      "messageRow " +
      (mine ? "mine" : "other");

    const bubble =
      document.createElement("div");

    bubble.className = "messageBubble";

    const time =
      new Date(
        message.created_at
      ).toLocaleTimeString(
        "ru-RU",
        {
          hour: "2-digit",
          minute: "2-digit"
        }
      );

    let reply = "";

    if (message.reply_text) {
      reply = `
        <div class="replyPreview">
          <b>
            ${escapeHtml(
              message.reply_display_name ||
              message.reply_username ||
              "Сообщение"
            )}
          </b>

          <span>
            ${escapeHtml(message.reply_text)}
          </span>
        </div>
      `;
    }

    const checks = mine
      ? `
        <span class="check">
          ${message.read_at ? "✓✓" : "✓"}
        </span>
      `
      : "";

    bubble.innerHTML = `
      ${reply}

      <span class="messageText">
        ${escapeHtml(message.text)}
      </span>

      <span class="messageMeta">
        ${time}
        ${checks}
      </span>
    `;

    row.appendChild(bubble);

    addSwipeReply(
      row,
      message
    );

    $("messages").appendChild(row);
  });
}

/* =========================
   ОТПРАВКА
========================= */

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
      text,
      replyTo: replyTo ? replyTo.id : null
    },
    result => {
      if (!result || !result.ok) {
        alert(
          result?.error ||
          "Не удалось отправить сообщение"
        );
        return;
      }

      $("messageInput").value = "";
      cancelReply();
    }
  );
}

/* =========================
   ПРОЧИТАНО
========================= */

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

/* =========================
   СВАЙП ДЛЯ ОТВЕТА
========================= */

function addSwipeReply(element, message) {
  let startX = 0;
  let distance = 0;

  element.addEventListener(
    "touchstart",
    event => {
      startX =
        event.touches[0].clientX;

      distance = 0;
    },
    { passive: true }
  );

  element.addEventListener(
    "touchmove",
    event => {
      distance =
        event.touches[0].clientX -
        startX;

      if (
        distance > 0 &&
        distance < 65
      ) {
        element.style.transform =
          `translateX(${distance}px)`;
      }
    },
    { passive: true }
  );

  element.addEventListener(
    "touchend",
    () => {
      element.style.transform = "";

      if (distance > 45) {
        setReply(message);
      }
    }
  );
}

function setReply(message) {
  replyTo = message;

  $("replyBox").hidden = false;

  $("replyName").textContent =
    message.sender_display_name ||
    message.sender_username ||
    "Пользователь";

  $("replyText").textContent =
    message.text;

  $("messageInput").focus();
}

function cancelReply() {
  replyTo = null;
  $("replyBox").hidden = true;
}

$("cancelReply").onclick = cancelReply;

/* =========================
   НАСТРОЙКИ
========================= */

$("settingsBtn").onclick = () => {
  $("settings").hidden = false;

  const name =
    me.display_name ||
    me.username;

  $("profileName").textContent = name;

  $("profileUsername").textContent =
    "@" + me.username;

  $("profileAvatar").textContent =
    getInitials(name);

  $("newName").value =
    me.display_name || "";
};

$("closeSettings").onclick = () => {
  $("settings").hidden = true;
};

$("saveName").onclick = async () => {
  try {
    const name =
      $("newName").value.trim();

    const user =
      await api(
        "/api/me",
        {
          method: "PATCH",
          body: JSON.stringify({
            displayName: name
          })
        }
      );

    me = {
      ...me,
      ...user
    };

    updateMyProfile();

    $("settings").hidden = true;

    loadChats();

  } catch (e) {
    alert(e.message);
  }
};

/* =========================
   ТЕМЫ
========================= */

document
  .querySelectorAll(".themeButtons button")
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
    document.body.classList.add(theme);
  }
}

/* =========================
   АВАТАР
========================= */

function getInitials(name) {
  const value =
    String(name || "").trim();

  if (!value) {
    return "?";
  }

  const words =
    value.split(/\s+/).filter(Boolean);

  if (words.length === 1) {
    return words[0][0].toUpperCase();
  }

  return (
    words[0][0] +
    words[1][0]
  ).toUpperCase();
}

/* =========================
   БЕЗОПАСНОСТЬ
========================= */

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* =========================
   ПРОКРУТКА
========================= */

function scrollBottom() {
  requestAnimationFrame(() => {
    const messages = $("messages");

    messages.scrollTop =
      messages.scrollHeight;
  });
}

/* =========================
   ВЫХОД
========================= */

$("logout").onclick = () => {
  logout();
};

function logout() {
  localStorage.removeItem("mtalk_token");

  token = null;

  if (socket) {
    socket.disconnect();
  }

  location.reload();
}

/* =========================
   СТАРТ
========================= */

if (token) {
  startApp();
}
