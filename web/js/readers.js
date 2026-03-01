/**
 * @fileoverview Reader management functions.
 */

/**
 * Fetches and displays all readers in the readers table.
 * Shows reader ID, key version, bound doors, and delete button.
 * @returns {Promise<void>}
 */
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

/**
 * Creates or updates a reader with the specified ID and key version.
 * Reads values from reader_id and reader_kv input fields.
 * @returns {Promise<void>}
 */
async function upsertReader() {
  await api("/api/readers", {
    method: "POST",
    body: JSON.stringify({
      reader_id: Number(document.getElementById("reader_id").value),
      current_key_version: Number(document.getElementById("reader_kv").value)
    })
  });
  clearInputs(["reader_id", "reader_kv"]);
  reloadPageSoon();
}

/**
 * Binds a door to a reader, allowing the reader to control that door.
 * Reads values from bind_reader_id and bind_door_id input fields.
 * @returns {Promise<void>}
 */
async function bindDoor() {
  const rid = Number(document.getElementById("bind_reader_id").value);
  const did = Number(document.getElementById("bind_door_id").value);
  await api(`/api/readers/${rid}/doors`, { method: "POST", body: JSON.stringify({ door_id: did }) });
  clearInputs(["bind_reader_id", "bind_door_id"]);
  reloadPageSoon();
}

/**
 * Deletes a reader by ID.
 * @param {number} rid - The reader ID to delete.
 * @returns {Promise<void>}
 */
async function delReader(rid) {
  await api(`/api/readers/${rid}`, { method: "DELETE" });
  reloadPageSoon();
}
