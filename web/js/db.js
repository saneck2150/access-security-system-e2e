/**
 * @fileoverview Database export and import functions.
 */

/**
 * Downloads the current database as a SQLite file.
 * Triggers a browser download of "access.db".
 * @returns {Promise<void>}
 */
async function exportDb() {
  const r = await fetch("/api/db/export", {
    headers: token() ? { "X-Admin-Token": token() } : {}
  });
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "access.db";
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Uploads and imports a database file, replacing the current database.
 * Reads file from dbfile input, displays result in db_status element.
 * @returns {Promise<void>}
 */
async function importDb() {
  const f = document.getElementById("dbfile").files[0];
  if (!f) return;
  const fd = new FormData();
  fd.append("db", f);

  const opt = { method: "POST", body: fd, headers: {} };
  if (token()) opt.headers["X-Admin-Token"] = token();

  const r = await fetch("/api/db/import", opt);
  const t = await r.text();
  document.getElementById("db_status").textContent = t;
  reloadPageSoon();
}
