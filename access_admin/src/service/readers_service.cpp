#include <mutex>
#include <unordered_map>

#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <access_admin/service/readers_service.hpp>

namespace admin::service {

ServiceResult listReaders(AppState& app) {
    std::lock_guard<std::mutex> lk(app.m);

    const auto readers = app.store->listReaders();
    const auto doors = app.store->listReaderDoors(0);

    std::unordered_map<uint32_t, std::vector<uint32_t>> byReader;
    for (const auto& d : doors) {
        byReader[d.reader_id].push_back(d.door_id);
    }

    json out;
    out["readers"] = json::array();
    for (const auto& r : readers) {
        out["readers"].push_back({{"reader_id", r.reader_id},
            {"current_key_version", r.current_key_version},
            {"doors", byReader[r.reader_id]}});
    }

    return okResult(out);
}

ServiceResult upsertReader(AppState& app, uint32_t reader_id, uint32_t key_version) {
    std::lock_guard<std::mutex> lk(app.m);

    app.store->upsertReader(reader_id, key_version);
    app.events.push({.ts_unix_ms = nowUnixMs(),
        .kind = "admin",
        .message = "upsertReader",
        .reader_id = reader_id});

    return okResult({{"ok", true}});
}

ServiceResult deleteReader(AppState& app, uint32_t reader_id) {
    std::lock_guard<std::mutex> lk(app.m);

    app.store->deleteReader(reader_id);
    app.events.push({.ts_unix_ms = nowUnixMs(),
        .kind = "admin",
        .message = "deleteReader",
        .reader_id = reader_id});

    return okResult({{"ok", true}});
}

ServiceResult bindDoor(AppState& app, uint32_t reader_id, uint32_t door_id) {
    std::lock_guard<std::mutex> lk(app.m);

    app.store->allowDoorForReader(reader_id, door_id);
    app.events.push({.ts_unix_ms = nowUnixMs(),
        .kind = "admin",
        .message = "bindDoor",
        .reader_id = reader_id,
        .door_id = door_id});

    return okResult({{"ok", true}});
}

ServiceResult unbindDoor(AppState& app, uint32_t reader_id, uint32_t door_id) {
    std::lock_guard<std::mutex> lk(app.m);

    app.store->revokeDoorForReader(reader_id, door_id);
    app.events.push({.ts_unix_ms = nowUnixMs(),
        .kind = "admin",
        .message = "unbindDoor",
        .reader_id = reader_id,
        .door_id = door_id});

    return okResult({{"ok", true}});
}

}  // namespace admin::service
