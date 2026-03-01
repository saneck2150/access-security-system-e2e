/**
 * @fileoverview Door role management functions.
 */

/**
 * Fetches and displays all door-role mappings in the door_roles table.
 * @returns {Promise<void>}
 */
async function loadDoorRoles() {
  const data = await api("/api/door_roles");
  let html = "<table><tr><th>door</th><th>role</th></tr>";
  for (const x of data.door_roles) {
    html += `<tr><td>${x.door_id}</td><td>${x.role}</td></tr>`;
  }
  html += "</table>";
  document.getElementById("door_roles_table").innerHTML = html;
}

/**
 * Allows a role to access a door.
 * Reads values from dr_door and dr_role input fields.
 * @returns {Promise<void>}
 */
async function allowRole() {
  await api("/api/door_roles", {
    method: "POST",
    body: JSON.stringify({
      door_id: Number(document.getElementById("dr_door").value),
      role: document.getElementById("dr_role").value
    })
  });
  clearInputs(["dr_door", "dr_role"]);
  reloadPageSoon();
}

/**
 * Revokes a role's access to a door.
 * Reads values from dr_door and dr_role input fields.
 * @returns {Promise<void>}
 */
async function revokeRole() {
  await api("/api/door_roles", {
    method: "DELETE",
    body: JSON.stringify({
      door_id: Number(document.getElementById("dr_door").value),
      role: document.getElementById("dr_role").value
    })
  });
  clearInputs(["dr_door", "dr_role"]);
  reloadPageSoon();
}
