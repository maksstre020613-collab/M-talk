let token = localStorage.getItem("mtalk_token");
let me = null;
let socket = null;
let currentChat = null;

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

    localStorage.setItem(
      "mtalk_token",
      token
    );

    await startApp();
  } catch (e) {
    $("authError").textContent = e.message;
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

    localStorage.setItem(
      "mtalk_token",
      token
    );

    await startApp();
  } catch (e) {
    $("authError").textContent = e.message;
  }
}

async function startApp() {
  try {
    me = await api("/api/me");

    $("auth").classList.add("hidden");
    $("app").classList.remove("hidden");

    $("currentUser").textContent =
      "@" + me.username;

    connectSocket();
    await loadChats();
  } catch {
    logout();
  }
}

function connectSocket() {
  if (socket) socket.disconnect();

  socket = io({
    auth: { token }
  });

  socket.on("connect", () => {
    if (currentChat) {
      socket.emit("joinChat", currentChat);
    }
  });

  socket.on("newMessage", message => {
    if (
      Number(message.chat_id) !==
      Number(currentChat)
    ) {
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

  if (!q) return;

  try {
    const users = await api(
      "/api/users?q=" +
      encodeURIComponent(q)
    );

    users.forEach(user => {
      const button =
        document.createElement("button");

      button.className = "user-result";
      button.textContent =
        "@" + user.username;

      button.addEventListener(
        "click",
        () => openUser(user)
      );

      box.appendChild(button);
    });
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
    await loadChats();
  } catch (e) {
    alert(e.message);
  }
}

async function loadChats() {
  try {
    const chats = await api("/api/chats");
    const box = $("chats");

    box.innerHTML = "";

    chats.forEach(chat => {
      const button =
        document.createElement("button");

      button.className = "chat-item";

      const avatar =
        document.createElement("div");

      avatar.className = "avatar";
      avatar.textContent =
        chat.username[0].toUpperCase();

      const info =
        document.createElement("div");

      info.style.minWidth = "0";

      const name =
        document.createElement("div");

      name.className = "chat-name";
      name.textContent =
        "@" + chat.username;

      const last =
        document.createElement("div");

      last.className = "last";
      last.textContent =
        chat.last_message ||
        "Нет сообщений";

      info.appendChild(name);
      info.appendChild(last);

      button.appendChild(avatar);
      button.appendChild(info);

      button.addEventListener(
        "click",
        () => openChat(
          chat.id,
          {
            id: chat.user_id,
            username: chat.username
          }
        )
      );

      box.appendChild(button);
    });
  } catch {}
}

async function openChat(chatId, user) {
  currentChat = chatId;

  $("chatTitle").textContent =
    "@" + user.username;

  $("app").classList.add("chat-open");

  socket?.emit("joinChat", chatId);

  $("messages").innerHTML = "";

  try {
    const messages = await api(
      "/api/chats/" +
      chatId +
      "/messages"
    );

    messages.forEach(renderMessage);

    scrollMessages();
  } catch (e) {
    $("messages").innerHTML =
      '<div class="empty">' +
      e.message +
      "</div>";
  }
}

function renderMessage(message) {
  const box = $("messages");

  const empty =
    box.querySelector(".empty");

  if (empty) empty.remove();

  const mine =
    Number(message.sender_id) ===
    Number(me.id);

  const row =
    document.createElement("div");

  row.className =
    "msg-row" +
    (mine ? " mine" : "");

  const msg =
    document.createElement("div");

  msg.className = "msg";

  const user =
    document.createElement("div");

  user.className = "msg-user";

  user.textContent =
    mine
      ? "Вы"
      : "@" + message.sender_username;

  const text =
    document.createElement("div");

  text.textContent = message.text;

  const time =
    document.createElement("span");

  time.className = "time";

  time.textContent =
    new Date(
      message.created_at
    ).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit"
    });

  msg.appendChild(user);
  msg.appendChild(text);
  msg.appendChild(time);

  row.appendChild(msg);
  box.appendChild(row);
}

function scrollMessages() {
  const box = $("messages");

  requestAnimationFrame(() => {
    box.scrollTop =
      box.scrollHeight;
  });
}

function sendMessage() {
  const input =
    $("messageInput");

  const text =
    input.value.trim();

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
        alert(
          result?.error ||
          "Ошибка отправки"
        );

        return;
      }

      input.value = "";
      input.focus();
    }
  );
}

function logout() {
  localStorage.removeItem(
    "mtalk_token"
  );

  token = null;
  currentChat = null;

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

$("loginBtn").addEventListener(
  "click",
  login
);

$("registerBtn").addEventListener(
  "click",
  register
);

$("logoutBtn").addEventListener(
  "click",
  logout
);

$("sendBtn").addEventListener(
  "click",
  sendMessage
);

$("search").addEventListener(
  "input",
  searchUsers
);

$("backBtn").addEventListener(
  "click",
  () => {
    $("app").classList.remove(
      "chat-open"
    );
  }
);

$("messageInput").addEventListener(
  "keydown",
  event => {
    if (event.key === "Enter") {
      sendMessage();
    }
  }
);

if (token) {
  startApp();
                  }
