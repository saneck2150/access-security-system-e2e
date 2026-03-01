#include <access_admin/app_state.hpp>
#include <access_admin/service/events_service.hpp>

namespace admin::service {

ServiceResult getEvents(AppState& app, uint64_t after_id, size_t limit) {
    auto evs = app.events.getAfter(after_id, limit);

    json out;
    out["last_id"] = app.events.lastId();
    out["events"] = json::array();

    for (const auto& e : evs) {
        out["events"].push_back({
            {"id", e.id},
            {"ts_unix_ms", e.ts_unix_ms},
            {"kind", e.kind},
            {"message", e.message},
            {"reader_id", e.reader_id},
            {"door_id", e.door_id},
            {"seq", e.seq},
            {"allow", e.allow},
            {"reason", e.reason},
        });
    }

    return okResult(out);
}

}  // namespace admin::service
