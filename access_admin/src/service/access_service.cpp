#include <mutex>

#include <access_admin/app_state.hpp>
#include <access_admin/service/access_service.hpp>

namespace admin::service {

ServiceResult checkAccess(AppState& app, const std::vector<uint8_t>& frame_bytes) {
    std::lock_guard<std::mutex> lk(app.m);

    auto r = app.engine->handleFrameBytes(frame_bytes, app.replayByReader);

    return okResult({{"allow", r.allow}, {"reason", r.reason}});
}

}  // namespace admin::service
