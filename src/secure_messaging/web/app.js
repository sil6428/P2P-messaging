const state = {
  csrf: null,
  profile: null,
  contacts: [],
  selectedId: null,
  selectedConversation: null,
  filter: "active",
  attachment: null,
  reply: null,
  poller: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (state.csrf && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
  return payload;
}

let toastTimer;
function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.hidden = true; }, 4500);
}

function initials(name) {
  return (name || "?").trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
}

function shortTime(value) {
  if (!value) return "";
  const date = new Date(value);
  const today = new Date();
  if (date.toDateString() === today.toDateString()) return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return date.toLocaleDateString([], { month: "short", day: "numeric" });
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function setListener(listener) {
  const connection = $("#connection");
  connection.classList.toggle("online", Boolean(listener?.online));
  connection.classList.toggle("error", Boolean(listener?.error));
  connection.querySelector("span:last-child").textContent = listener?.online
    ? `Listening locally on port ${listener.port}`
    : listener?.error || "Listener offline";
}

async function bootstrap() {
  try {
    const session = await api("/api/session");
    if (!session.authenticated) {
      showAuth(session.setup_required);
      return;
    }
    enterApp(session);
  } catch (error) {
    showAuth(false);
    toast(error.message, true);
  }
}

function showAuth(setupRequired) {
  $("#app-shell").hidden = true;
  $("#auth-shell").hidden = false;
  $("#setup-form").hidden = !setupRequired;
  $("#login-form").hidden = setupRequired;
  $("#auth-title").textContent = setupRequired ? "Create this device" : "Unlock Relay";
  $("#auth-intro").textContent = setupRequired
    ? "Create a password-protected identity and an encrypted local history."
    : "Your private keys stay on this computer.";
}

async function enterApp(session) {
  state.csrf = session.csrf_token;
  state.profile = session.profile;
  $("#auth-shell").hidden = true;
  $("#app-shell").hidden = false;
  $("#profile-name").textContent = session.profile.display_name;
  $("#profile-avatar").textContent = initials(session.profile.display_name);
  $("#own-peer-card").value = session.profile.peer_card;
  setListener(session.listener);
  await loadContacts();
  clearInterval(state.poller);
  state.poller = setInterval(refreshVisibleConversation, 4000);
}

async function loadContacts() {
  const payload = await api("/api/contacts");
  state.contacts = payload.contacts;
  renderContacts();
}

function visibleContacts() {
  const query = $("#contact-search").value.trim().toLowerCase();
  return state.contacts.filter((contact) => {
    const matches = !query || contact.display_name.toLowerCase().includes(query) || contact.endpoint.toLowerCase().includes(query);
    if (!matches) return false;
    if (state.filter === "pinned") return contact.pinned;
    if (state.filter === "archived") return contact.archived;
    return !contact.archived;
  });
}

function renderContacts() {
  const container = $("#conversation-list");
  const contacts = visibleContacts();
  if (!contacts.length) {
    container.innerHTML = `<div class="list-empty">${state.contacts.length ? "No conversations match this view." : "No peers yet. Import a signed peer card to begin."}</div>`;
    return;
  }
  container.innerHTML = contacts.map((contact) => `
    <button class="conversation-item ${contact.id === state.selectedId ? "active" : ""}" data-contact-id="${contact.id}">
      <span class="contact-avatar">${escapeHtml(initials(contact.display_name))}</span>
      <span class="conversation-copy">
        <span class="conversation-line"><strong>${escapeHtml(contact.display_name)}</strong>${contact.verified ? '<span class="verified-mark" title="Fingerprint verified">◆</span>' : ""}</span>
        <p>${escapeHtml(contact.last_message || (contact.verified ? "Ready for encrypted messages" : "Fingerprint verification required"))}</p>
      </span>
      <span class="conversation-meta"><span>${escapeHtml(shortTime(contact.last_message_at))}</span>${contact.pinned ? '<span class="pin-mark">PIN</span>' : ""}</span>
    </button>
  `).join("");
  $$(".conversation-item").forEach((button) => button.addEventListener("click", () => selectConversation(button.dataset.contactId)));
}

async function selectConversation(contactId, query = "") {
  if (state.selectedId !== contactId) {
    state.reply = null;
    state.attachment = null;
    renderReply();
    renderAttachment();
  }
  state.selectedId = contactId;
  renderContacts();
  const suffix = query ? `?q=${encodeURIComponent(query)}` : "";
  try {
    const conversation = await api(`/api/conversations/${contactId}${suffix}`);
    state.selectedConversation = conversation;
    renderConversation();
    $("#empty-state").hidden = true;
    $("#chat-view").hidden = false;
    $(".conversation-panel").classList.add("mobile-hidden");
    $(".chat-panel").classList.remove("mobile-hidden");
  } catch (error) {
    toast(error.message, true);
  }
}

function renderConversation() {
  const { contact, messages } = state.selectedConversation;
  $("#chat-name").textContent = contact.display_name;
  $("#chat-avatar").textContent = initials(contact.display_name);
  $("#chat-security").textContent = contact.verified ? "Verified peer · encrypted direct session" : "Fingerprint verification required";
  $("#chat-security").classList.toggle("secure", contact.verified);
  $("#detail-name").textContent = contact.display_name;
  $("#detail-avatar").textContent = initials(contact.display_name);
  $("#detail-endpoint").textContent = contact.endpoint;
  $("#detail-fingerprint").textContent = contact.fingerprint;
  $("#trust-state").textContent = contact.verified ? "Fingerprint verified" : "Unverified contact";
  $("#trust-card").classList.toggle("verified", contact.verified);
  $("#verify-button").hidden = contact.verified;
  $("#pin-toggle").checked = contact.pinned;
  $("#mute-toggle").checked = contact.muted;
  $("#archive-toggle").checked = contact.archived;
  $("#message-input").disabled = !contact.verified;
  $("#composer .send-button").disabled = !contact.verified;
  $("#message-input").placeholder = contact.verified ? "Write an encrypted message" : "Verify this contact before messaging";
  renderMessages(messages);
  restoreDraft(contact.id);
}

function renderMessages(messages) {
  const container = $("#message-list");
  if (!messages.length) {
    container.innerHTML = '<div class="message-empty">No messages in this view.<br>Start with a short test message after verifying the fingerprint.</div>';
    return;
  }
  let lastDay = "";
  const parts = [];
  const byId = new Map(messages.map((message) => [message.id, message]));
  for (const message of messages) {
    const date = new Date(message.sent_at);
    const day = date.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
    if (day !== lastDay) {
      parts.push(`<div class="day-divider">${escapeHtml(day.toUpperCase())}</div>`);
      lastDay = day;
    }
    const attachment = message.attachment ? `
      <div class="attachment"><strong>${escapeHtml(message.attachment.filename)}</strong><span>${escapeHtml(formatBytes(message.attachment.size_bytes))} · SHA-256 ${escapeHtml(message.attachment.sha256.slice(0, 12))}…</span></div>` : "";
    const replied = message.reply_to ? byId.get(message.reply_to) : null;
    const quote = message.reply_to ? `<div class="reply-quote">${escapeHtml(replied ? `${replied.sender_name}: ${replied.body.slice(0, 110)}` : "Referenced earlier message")}</div>` : "";
    parts.push(`
      <article class="message ${message.direction === "sent" ? "sent" : "received"}">
        ${quote}<p>${escapeHtml(message.body)}</p>${attachment}
        <footer><span>${escapeHtml(date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))}</span><span>${message.direction === "sent" ? "ACKNOWLEDGED" : "AUTHENTICATED"}</span></footer>
        <button class="reply-action" data-reply-id="${escapeHtml(message.id)}">Reply</button>
      </article>
    `);
  }
  container.innerHTML = parts.join("");
  $$(".reply-action").forEach((button) => button.addEventListener("click", () => {
    const message = byId.get(button.dataset.replyId);
    state.reply = { id: message.id, sender_name: message.sender_name, body: message.body };
    renderReply();
    $("#message-input").focus();
  }));
  container.scrollTop = container.scrollHeight;
}

async function refreshVisibleConversation() {
  if (!state.csrf) return;
  try {
    const session = await api("/api/session");
    if (!session.authenticated) return showAuth(false);
    setListener(session.listener);
    await loadContacts();
    if (state.selectedId) {
      const query = $("#message-search").value.trim();
      const suffix = query ? `?q=${encodeURIComponent(query)}` : "";
      state.selectedConversation = await api(`/api/conversations/${state.selectedId}${suffix}`);
      renderConversation();
    }
  } catch (error) {
    console.debug("Background refresh paused", error);
  }
}

function draftKey(contactId) { return `relay-draft:${contactId}`; }
function restoreDraft(contactId) {
  const draft = localStorage.getItem(draftKey(contactId)) || "";
  if ($("#message-input").value !== draft) $("#message-input").value = draft;
  $("#draft-state").textContent = draft ? "DRAFT" : "";
}

async function sha256(file) {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function renderAttachment() {
  const preview = $("#attachment-preview");
  preview.hidden = !state.attachment;
  if (!state.attachment) return;
  $("#attachment-name").textContent = state.attachment.filename;
  $("#attachment-meta").textContent = `${formatBytes(state.attachment.size_bytes)} · SHA-256 ${state.attachment.sha256.slice(0, 18)}…`;
}

function renderReply() {
  const preview = $("#reply-preview");
  preview.hidden = !state.reply;
  if (!state.reply) return;
  $("#reply-name").textContent = `Replying to ${state.reply.sender_name}`;
  $("#reply-body").textContent = state.reply.body;
}

async function savePreferences() {
  if (!state.selectedId) return;
  const payload = {
    pinned: $("#pin-toggle").checked,
    muted: $("#mute-toggle").checked,
    archived: $("#archive-toggle").checked,
  };
  try {
    await api(`/api/conversations/${state.selectedId}/preferences`, { method: "PUT", body: JSON.stringify(payload) });
    Object.assign(state.selectedConversation.contact, payload);
    await loadContacts();
  } catch (error) { toast(error.message, true); }
}

function openContactDialog(prefill = "") {
  $("#verify-fingerprint-input").value = prefill;
  $("#contact-dialog").showModal();
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  try {
    const data = Object.fromEntries(new FormData(event.currentTarget));
    const session = await api("/api/login", { method: "POST", body: JSON.stringify(data) });
    await enterApp(session);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});

$("#same-password").addEventListener("change", (event) => {
  const form = $("#setup-form");
  const history = form.elements.history_password;
  history.value = event.currentTarget.checked ? form.elements.password.value : "";
  history.readOnly = event.currentTarget.checked;
});

$("#setup-form").elements.password.addEventListener("input", (event) => {
  if ($("#same-password").checked) $("#setup-form").elements.history_password.value = event.currentTarget.value;
});

$("#setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (form.elements.password.value !== form.elements.password_confirm.value) return toast("Device passwords do not match.", true);
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  const data = Object.fromEntries(new FormData(form));
  delete data.password_confirm;
  try {
    const session = await api("/api/setup", { method: "POST", body: JSON.stringify(data) });
    await enterApp(session);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});

$("#logout-button").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (_) { /* lock locally anyway */ }
  state.csrf = null;
  state.selectedId = null;
  clearInterval(state.poller);
  showAuth(false);
});

$("#add-contact-button").addEventListener("click", () => openContactDialog());
$("#empty-add-button").addEventListener("click", () => openContactDialog());
$("#verify-button").addEventListener("click", () => openContactDialog(state.selectedConversation?.contact.fingerprint || ""));
$("#show-card-button").addEventListener("click", () => $("#peer-card-dialog").showModal());
$("#copy-card-button").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#own-peer-card").value);
  toast("Peer card copied.");
});

$("#import-contact-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api("/api/contacts", { method: "POST", body: JSON.stringify({ peer_card: $("#peer-card-input").value }) });
    $("#verify-fingerprint-input").value = result.fingerprint;
    await loadContacts();
    toast(`${result.display_name} imported. Compare the fingerprint before verifying.`);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});

$("#verify-contact-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api("/api/contacts/verify", { method: "POST", body: JSON.stringify({ fingerprint: $("#verify-fingerprint-input").value }) });
    await loadContacts();
    $("#contact-dialog").close();
    toast(`${result.display_name}'s fingerprint is now marked verified.`);
    await selectConversation(result.id);
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});

$("#contact-search").addEventListener("input", renderContacts);
$$('.filter').forEach((button) => button.addEventListener("click", () => {
  $$(".filter").forEach((item) => item.classList.remove("active"));
  button.classList.add("active");
  state.filter = button.dataset.filter;
  renderContacts();
}));

let searchTimer;
$("#message-search").addEventListener("input", (event) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => selectConversation(state.selectedId, event.currentTarget.value.trim()), 250);
});

$("#message-input").addEventListener("input", (event) => {
  if (!state.selectedId) return;
  const value = event.currentTarget.value;
  localStorage.setItem(draftKey(state.selectedId), value);
  $("#draft-state").textContent = value ? "DRAFT" : "";
  event.currentTarget.style.height = "auto";
  event.currentTarget.style.height = `${Math.min(event.currentTarget.scrollHeight, 110)}px`;
});

$("#attachment-button").addEventListener("click", () => $("#attachment-input").click());
$("#attachment-input").addEventListener("change", async (event) => {
  const [file] = event.currentTarget.files;
  if (!file) return;
  if (file.name.includes("/") || file.name.includes("\\")) return toast("Attachment filename is invalid.", true);
  toast("Calculating the file integrity digest…");
  state.attachment = { filename: file.name, size_bytes: file.size, sha256: await sha256(file) };
  renderAttachment();
});
$("#remove-attachment").addEventListener("click", () => { state.attachment = null; $("#attachment-input").value = ""; renderAttachment(); });
$("#remove-reply").addEventListener("click", () => { state.reply = null; renderReply(); });

$("#composer").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedId) return;
  const input = $("#message-input");
  const body = input.value.trim();
  if (!body) return;
  const button = event.currentTarget.querySelector(".send-button");
  button.disabled = true;
  button.textContent = "…";
  try {
    await api(`/api/conversations/${state.selectedId}/messages`, { method: "POST", body: JSON.stringify({ body, attachment: state.attachment, reply_to: state.reply?.id || null }) });
    input.value = "";
    input.style.height = "auto";
    localStorage.removeItem(draftKey(state.selectedId));
    $("#draft-state").textContent = "";
    state.attachment = null;
    state.reply = null;
    renderAttachment();
    renderReply();
    await selectConversation(state.selectedId, $("#message-search").value.trim());
    await loadContacts();
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; button.textContent = "Send"; }
});

["#pin-toggle", "#mute-toggle", "#archive-toggle"].forEach((selector) => $(selector).addEventListener("change", savePreferences));
$("#details-toggle").addEventListener("click", () => { $("#details-panel").hidden = false; });
$("#details-close").addEventListener("click", () => { $("#details-panel").hidden = true; });
$("#restart-listener").addEventListener("click", async () => {
  try { setListener(await api("/api/listener/restart", { method: "POST" })); toast("Local listener restarted."); }
  catch (error) { toast(error.message, true); }
});

$(".chat-header").addEventListener("click", (event) => {
  if (window.innerWidth <= 760 && event.offsetX < 44) {
    $(".chat-panel").classList.add("mobile-hidden");
    $(".conversation-panel").classList.remove("mobile-hidden");
  }
});

bootstrap();
