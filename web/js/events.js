/**
 * @fileoverview Runtime event polling and scan simulation functions.
 */

/** @type {number} ID of the last received event (for polling). */
let afterId = 0;

/** @type {number|null} Polling interval ID. */
let pollIntervalId = null;

/**
 * Formats an event object into a human-readable log line.
 * @param {Object} e - Event object from the API.
 * @param {number} e.id - Event ID.
 * @param {number} e.ts_unix_ms - Timestamp in milliseconds.
 * @param {string} e.kind - Event type (frame, decision, audit, admin).
 * @param {number} e.reader_id - Reader ID.
 * @param {number} e.door_id - Door ID.
 * @param {number} e.seq - Sequence number.
 * @param {boolean} e.allow - Access granted or denied.
 * @param {string} e.reason - Result reason.
 * @param {string} e.message - Event message.
 * @returns {string} Formatted log line with newline.
 */
function formatEvent(e) {
  const base = `[${String(e.id).padStart(6, "0")}] ${fmtTime(e.ts_unix_ms)} ${String(e.kind).padEnd(8, " ")} `;

  if (e.kind === "admin") {
    return `${base}r=${e.reader_id} d=${e.door_id} :: ${e.message}\n`;
  }

  const allow = e.allow ? "ALLOW" : "DENY ";
  const reason = (e.reason && e.reason.length) ? ` reason=${e.reason}` : "";
  return `${base}r=${e.reader_id} d=${e.door_id} seq=${e.seq} ${allow}${reason} :: ${e.message}\n`;
}

/**
 * Polls the server for new events and appends them to the log display.
 * Updates afterId to track the last received event.
 * Stops polling on auth errors.
 * @returns {Promise<void>}
 */
async function pollEvents() {
  try {
    const data = await api(`/api/events?after=${afterId}&limit=200`);
    afterId = data.last_id;
    const log = document.getElementById("log");
    for (const e of data.events) {
      log.textContent += formatEvent(e);
      log.scrollTop = log.scrollHeight;
    }
  } catch (e) {
    if (String(e).includes("401") || String(e).includes("unauthorized")) {
      stopEventPolling();
      const log = document.getElementById("log");
      log.textContent += `[ERROR] Auth failed - polling stopped. Check token.\n`;
    }
  }
}

/**
 * Starts the event polling interval (every 500ms).
 */
function startEventPolling() {
  if (pollIntervalId) return;
  pollIntervalId = setInterval(pollEvents, 500);
}

/**
 * Stops the event polling interval.
 */
function stopEventPolling() {
  if (pollIntervalId) {
    clearInterval(pollIntervalId);
    pollIntervalId = null;
  }
}
