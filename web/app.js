let afterId = 0;
const LAST_SECTION_KEY = "last_section";

function token() { return localStorage.getItem("admin_token") || ""; }
function saveToken() {
  localStorage.setItem("admin_token", document.getElementById("token").value);
}

document.getElementById("token").value = token();

function clearInputs(ids) {
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.type === "file") {
      el.value = "";
      return;
    }
    el.value = "";
  });
}

function reloadPageSoon(delayMs = 150) {
  setTimeout(() => window.location.reload(), delayMs);
}

function show(id) {
  document.querySelectorAll("section").forEach(s => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
  localStorage.setItem(LAST_SECTION_KEY, id);
  if (id === "readers") loadReaders();
  if (id === "door_roles") loadDoorRoles();
  if (id === "cards") loadCards();
  if (id === "audit") loadAudit();
}

function fmtTime(ms) {
  const d = new Date(ms);
  const iso = d.toISOString();
  return iso.replace("T", " ").replace("Z", "");
}

function formatEvent(e) {
  const base = `[${String(e.id).padStart(6, "0")}] ${fmtTime(e.ts_unix_ms)} ${String(e.kind).padEnd(8, " ")} `;

  if (e.kind === "admin") {
    return `${base}r=${e.reader_id} d=${e.door_id} :: ${e.message}\n`;
  }

  const allow = e.allow ? "ALLOW" : "DENY ";
  const reason = (e.reason && e.reason.length) ? ` reason=${e.reason}` : "";
  return `${base}r=${e.reader_id} d=${e.door_id} seq=${e.seq} ${allow}${reason} :: ${e.message}\n`;
}

async function api(path, opt = {}) {
  opt.headers = opt.headers || {};
  if (token()) opt.headers["X-Admin-Token"] = token();
  if (opt.body && !(opt.body instanceof FormData)) {
    opt.headers["Content-Type"] = "application/json";
  }
  const r = await fetch(path, opt);
  if (!r.ok) {
    const t = await r.text();
    throw new Error(r.status + ": " + t);
  }
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("application/json")) return await r.json();
  return await r.text();
}

async function loadReaders() {
  const data = await api("/api/readers");
  let html = "<table><tr><th>reader</th><th>kv</th><th>doors</th><th>actions</th></tr>";
  for (const r of data.readers) {
    html += `<tr>
      <td>${r.reader_id}</td>
      <td>${r.current_key_version}</td>
      <td>${(r.doors||[]).join(", ")}</td>
      <td><button onclick="delReader(${r.reader_id})">Delete</button></td>
    </tr>`;
  }
  html += "</table>";
  document.getElementById("readers_table").innerHTML = html;
}

async function upsertReader() {
  await api("/api/readers", {
    method:"POST",
    body: JSON.stringify({
      reader_id: Number(document.getElementById("reader_id").value),
      current_key_version: Number(document.getElementById("reader_kv").value)
    })
  });
  clearInputs(["reader_id", "reader_kv"]);
  reloadPageSoon();
}

async function bindDoor() {
  const rid = Number(document.getElementById("bind_reader_id").value);
  const did = Number(document.getElementById("bind_door_id").value);
  await api(`/api/readers/${rid}/doors`, { method:"POST", body: JSON.stringify({door_id: did}) });
  clearInputs(["bind_reader_id", "bind_door_id"]);
  reloadPageSoon();
}

async function delReader(rid) {
  await api(`/api/readers/${rid}`, { method:"DELETE" });
  reloadPageSoon();
}

async function loadDoorRoles() {
  const data = await api("/api/door_roles");
  let html = "<table><tr><th>door</th><th>role</th></tr>";
  for (const x of data.door_roles) {
    html += `<tr><td>${x.door_id}</td><td>${x.role}</td></tr>`;
  }
  html += "</table>";
  document.getElementById("door_roles_table").innerHTML = html;
}

async function allowRole() {
  await api("/api/door_roles", { method:"POST", body: JSON.stringify({
    door_id: Number(document.getElementById("dr_door").value),
    role: document.getElementById("dr_role").value
  })});
  clearInputs(["dr_door", "dr_role"]);
  reloadPageSoon();
}

async function revokeRole() {
  await api("/api/door_roles", { method:"DELETE", body: JSON.stringify({
    door_id: Number(document.getElementById("dr_door").value),
    role: document.getElementById("dr_role").value
  })});
  clearInputs(["dr_door", "dr_role"]);
  reloadPageSoon();
}

async function loadCards() {
  const data = await api("/api/cards?limit=200&offset=0");
  let html = "<table><tr><th>card_hmac</th><th>role</th></tr>";
  for (const x of data.cards) {
    html += `<tr><td>${x.card_hmac}</td><td>${x.role}</td></tr>`;
  }
  html += "</table>";
  document.getElementById("cards_table").innerHTML = html;
}

async function addCard() {
  const kvRaw = document.getElementById("card_kv").value.trim();
  const body = {
    card_id: document.getElementById("card_raw").value,
    role: document.getElementById("card_role").value
  };
  if (kvRaw) body.key_version = Number(kvRaw);

  await api("/api/cards", { method:"POST", body: JSON.stringify(body) });
  clearInputs(["card_raw", "card_role", "card_kv"]);
  reloadPageSoon();
}

async function deleteCard() {
  await api("/api/cards", { method:"DELETE", body: JSON.stringify({
    card_hmac: document.getElementById("card_hmac_del").value
  })});
  clearInputs(["card_hmac_del"]);
  reloadPageSoon();
}

async function loadAudit() {
  const data = await api("/api/audit?limit=200&offset=0");
  let html = "<table><tr><th>id</th><th>ts</th><th>reader</th><th>door</th><th>seq</th><th>allow</th><th>reason</th><th>card_hmac</th><th>action</th></tr>";
  for (const a of data.audit) {
    html += `<tr>
      <td>${a.id}</td><td>${a.ts_unix_ms}</td><td>${a.reader_id}</td><td>${a.door_id}</td>
      <td>${a.seq}</td><td>${a.allow}</td><td>${a.reason}</td><td>${a.card_hmac||""}</td><td>${a.action||""}</td>
    </tr>`;
  }
  html += "</table>";
  document.getElementById("audit_table").innerHTML = html;
}

async function verifyAudit() {
  const data = await api("/api/audit/verify", { method:"POST", body:"{}" });
  document.getElementById("audit_status").textContent = JSON.stringify(data, null, 2);
}

async function exportDb() {
  const r = await fetch("/api/db/export", { headers: token() ? {"X-Admin-Token": token()} : {} });
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "access.db";
  a.click();
  URL.revokeObjectURL(url);
}

async function importDb() {
  const f = document.getElementById("dbfile").files[0];
  if (!f) return;
  const fd = new FormData();
  fd.append("db", f);

  const opt = { method:"POST", body: fd, headers:{} };
  if (token()) opt.headers["X-Admin-Token"] = token();

  const r = await fetch("/api/db/import", opt);
  const t = await r.text();
  document.getElementById("db_status").textContent = t;
  reloadPageSoon();
}

async function pollEvents() {
  try {
    const data = await api(`/api/events?after=${afterId}&limit=200`);
    afterId = data.last_id;
    const log = document.getElementById("log");
    for (const e of data.events) {
      log.textContent += formatEvent(e);
      log.scrollTop = log.scrollHeight;
    }
  } catch (e) {}
}

async function simulateScan() {
  const cardId = document.getElementById("sim_card_id").value;
  const readerId = Number(document.getElementById("sim_reader_id").value);
  const doorId = Number(document.getElementById("sim_door_id").value);

  const body = { card_id: cardId, reader_id: readerId, door_id: doorId };

  try {
    const data = await api("/api/simulate_scan", { method:"POST", body: JSON.stringify(body) });
    document.getElementById("sim_result").textContent = JSON.stringify(data, null, 2);
    clearInputs(["sim_card_id", "sim_reader_id", "sim_door_id"]);
  } catch (e) {
    document.getElementById("sim_result").textContent = String(e);
  }
}

setInterval(pollEvents, 500);
const initialSection = localStorage.getItem(LAST_SECTION_KEY) || "readers";
show(initialSection);
