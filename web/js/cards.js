/**
 * @fileoverview Card management functions.
 */

/**
 * Fetches and displays all cards in the cards table.
 * Shows card HMAC (not raw ID) and assigned role.
 * @returns {Promise<void>}
 */
async function loadCards() {
  const data = await api("/api/cards?limit=200&offset=0");
  let html = "<table><tr><th>card_hmac</th><th>role</th></tr>";
  for (const x of data.cards) {
    html += `<tr><td>${x.card_hmac}</td><td>${x.role}</td></tr>`;
  }
  html += "</table>";
  document.getElementById("cards_table").innerHTML = html;
}

/**
 * Adds or updates a card with the specified role.
 * Reads values from card_raw, card_role, and card_kv input fields.
 * The server will hash the raw card ID before storage.
 * @returns {Promise<void>}
 */
async function addCard() {
  const kvRaw = document.getElementById("card_kv").value.trim();
  const body = {
    card_id: document.getElementById("card_raw").value,
    role: document.getElementById("card_role").value
  };
  if (kvRaw) body.key_version = Number(kvRaw);

  await api("/api/cards", { method: "POST", body: JSON.stringify(body) });
  clearInputs(["card_raw", "card_role", "card_kv"]);
  reloadPageSoon();
}

/**
 * Deletes a card by its HMAC.
 * Reads value from card_hmac_del input field.
 * @returns {Promise<void>}
 */
async function deleteCard() {
  await api("/api/cards", {
    method: "DELETE",
    body: JSON.stringify({
      card_hmac: document.getElementById("card_hmac_del").value
    })
  });
  clearInputs(["card_hmac_del"]);
  reloadPageSoon();
}
