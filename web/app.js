let afterId = 0;

function token() { return localStorage.getItem("admin_token") || ""; }
function saveToken() {
  localStorage.setItem("admin_token", document.getElementById("token").value);
}

document.getElementById("token").value = token();

function show(id) {
  document.querySelectorAll("section").forEach(s => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
  if (id === "readers") loadReaders();
  if (id === "door_roles") loadDoorRoles();
  if (id === "cards") loadCards();
  if (id === "audit") loadAudit();
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
  loadReaders();
}

async function bindDoor() {
  const rid = Number(document.getElementById("bind_reader_id").value);
  const did = Number(document.getElementById("bind_door_id").value);
  await api(`/api/readers/${rid}/doors`, { method:"POST", body: JSON.stringify({door_id: did}) });
  loadReaders();
}

async function delReader(rid) {
  await api(`/api/readers/${rid}`, { method:"DELETE" });
  loadReaders();
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
  loadDoorRoles();
}

async function revokeRole() {
  await api("/api/door_roles", { method:"DELETE", body: JSON.stringify({
    door_id: Number(document.getElementById("dr_door").value),
    role: document.getElementById("dr_role").value
  })});
  loadDoorRoles();
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
  loadCards();
}

async function deleteCard() {
  await api("/api/cards", { method:"DELETE", body: JSON.stringify({
    card_hmac: document.getElementById("card_hmac_del").value
  })});
  loadCards();
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

  loadReaders(); loadDoorRoles(); loadCards(); loadAudit();
}

async function pollEvents() {
  try {
    const data = await api(`/api/events?after=${afterId}&limit=200`);
    afterId = data.last_id;
    const log = document.getElementById("log");
    for (const e of data.events) {
      log.textContent += `[${e.id}] ${e.kind} r=${e.reader_id} d=${e.door_id} seq=${e.seq} allow=${e.allow} reason=${e.reason} :: ${e.message}\n`;
      log.scrollTop = log.scrollHeight;
    }
  } catch (e) {}
}

setInterval(pollEvents, 500);
show("readers");
