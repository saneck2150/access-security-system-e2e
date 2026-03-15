#include <mutex>

#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <access_admin/service/door_roles_service.hpp>

namespace admin::service {

ServiceResult listDoorRoles(AppState& app) {
    std::lock_guard<std::mutex> lk(app.m);

    auto rows = app.store->listDoorRoles(0);

    json out;
    out["door_roles"] = json::array();
    for (const auto& r : rows) {
        out["door_roles"].push_back({{"door_id", r.door_id}, {"role", r.role}});
    }

    return okResult(out);
}

ServiceResult allowRole(AppState& app, uint32_t door_id, const std::string& role) {
    std::lock_guard<std::mutex> lk(app.m);

    app.store->allowRole(door_id, role);
    app.events.push({.ts_unix_ms = nowUnixMs(),
        .kind = "admin",
        .message = "allowRole: " + role,
        .door_id = door_id});

    return okResult({{"ok", true}});
}

ServiceResult revokeRole(AppState& app, uint32_t door_id, const std::string& role) {
    std::lock_guard<std::mutex> lk(app.m);

    app.store->revokeRole(door_id, role);
    app.events.push({.ts_unix_ms = nowUnixMs(),
        .kind = "admin",
        .message = "revokeRole: " + role,
        .door_id = door_id});

    return okResult({{"ok", true}});
}

}  // namespace admin::service
