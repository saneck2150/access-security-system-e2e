/**
 * @fileoverview Navigation and page initialization.
 */

/** @const {string} localStorage key for remembering the last active section. */
const LAST_SECTION_KEY = "last_section";

/**
 * Shows a section and hides all others. Loads data for the selected section.
 * @param {string} id - The ID of the section to display.
 */
function show(id) {
  document.querySelectorAll("section").forEach(s => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
  localStorage.setItem(LAST_SECTION_KEY, id);
  if (id === "readers") loadReaders();
  if (id === "door_roles") loadDoorRoles();
  if (id === "cards") loadCards();
  if (id === "audit") {
    loadAudit();
    startAuditAutoRefresh();
  } else {
    stopAuditAutoRefresh();
  }
}

/**
 * Initializes the application on page load.
 * Restores token, starts event polling, and shows the last active section.
 */
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("token").value = token();
  startEventPolling();
  const initialSection = localStorage.getItem(LAST_SECTION_KEY) || "readers";
  show(initialSection);
});
