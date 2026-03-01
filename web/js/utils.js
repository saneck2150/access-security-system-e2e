/**
 * @fileoverview Shared utilities for API communication, token management, and helpers.
 */

/**
 * Retrieves the admin token from localStorage.
 * @returns {string} The stored admin token, or empty string if not set.
 */
function token() {
  return localStorage.getItem("admin_token") || "";
}

/**
 * Saves the admin token from the input field to localStorage.
 */
function saveToken() {
  localStorage.setItem("admin_token", document.getElementById("token").value);
}

/**
 * Clears the values of multiple input elements by ID.
 * @param {string[]} ids - Array of element IDs to clear.
 */
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

/**
 * Reloads the page after a short delay.
 * @param {number} [delayMs=150] - Milliseconds to wait before reload.
 */
function reloadPageSoon(delayMs = 150) {
  setTimeout(() => window.location.reload(), delayMs);
}

/**
 * Formats a Unix timestamp in milliseconds to a human-readable string.
 * @param {number} ms - Unix timestamp in milliseconds.
 * @returns {string} Formatted datetime string (YYYY-MM-DD HH:MM:SS.mmm).
 */
function fmtTime(ms) {
  const d = new Date(ms);
  const iso = d.toISOString();
  return iso.replace("T", " ").replace("Z", "");
}

/**
 * Makes an authenticated API request to the backend.
 * @param {string} path - API endpoint path (e.g., "/api/readers").
 * @param {Object} [opt={}] - Fetch options (method, body, headers).
 * @returns {Promise<Object|string>} Parsed JSON response or text.
 * @throws {Error} If response status is not OK (includes status and body).
 */
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
