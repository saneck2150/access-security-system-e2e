#include <mutex>

#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <access_admin/service/cards_service.hpp>
#include <access_decision/card_id_hasher.hpp>

namespace admin::service {

ServiceResult listCards(AppState& app, size_t limit, size_t offset) {
    std::lock_guard<std::mutex> lk(app.m);

    auto rows = app.store->listCards(limit, offset);

    json out;
    out["cards"] = json::array();
    for (const auto& r : rows) {
        out["cards"].push_back({{"card_hmac", r.card_hmac}, {"role", r.role}});
    }

    return okResult(out);
}

ServiceResult upsertCard(AppState& app,
    const std::string& card_id,
    const std::string& role,
    std::optional<uint32_t> key_version) {
    const uint32_t kv = key_version.value_or(app.cfg.keyManagement.currentKeyVersion);

    const auto pepper = app.keyManager.deriveCardPepper(kv);
    access_decision::CardIdHasher hasher(pepper);
    const std::string hmacHex = hasher.hmacHex(card_id);

    std::lock_guard<std::mutex> lk(app.m);
    app.store->upsertCardHmac(hmacHex, role);
    app.events.push(
        {.ts_unix_ms = nowUnixMs(), .kind = "admin", .message = "upsertCard role=" + role});

    return okResult({{"ok", true}, {"card_hmac", hmacHex}});
}

ServiceResult deleteCard(AppState& app, const std::string& card_hmac) {
    std::lock_guard<std::mutex> lk(app.m);

    app.store->deleteCardHmac(card_hmac);
    app.events.push({.ts_unix_ms = nowUnixMs(), .kind = "admin", .message = "deleteCard"});

    return okResult({{"ok", true}});
}

}  // namespace admin::service
