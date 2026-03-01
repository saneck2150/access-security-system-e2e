/**
 * @fileoverview Audit log viewing and verification functions.
 */

/**
 * Fetches and displays audit log entries in the audit table.
 * Shows: id, timestamp, reader, door, seq, allow/deny, reason, card_hmac, action.
 * @returns {Promise<void>}
 */
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

/**
 * Verifies the cryptographic integrity of the audit log chain.
 * Displays the verification result in the audit_status element.
 * @returns {Promise<void>}
 */
async function verifyAudit() {
  const data = await api("/api/audit/verify", { method: "POST", body: "{}" });
  document.getElementById("audit_status").textContent = JSON.stringify(data, null, 2);
}
