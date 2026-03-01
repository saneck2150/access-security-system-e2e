#include <mutex>

#include <access_admin/app_state.hpp>
#include <access_admin/service/audit_service.hpp>
#include <access_storage/audit_verify.hpp>
#include <sqlite3.h>

namespace admin::service {

namespace {

//! SQL query for audit log pagination.
constexpr const char* kAuditSelectSql =
    "SELECT id, ts_unix_ms, reader_id, door_id, seq, allow, reason, card_hmac, "
    "action "
    "FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?;";

//! Parses a single SQLite row into audit JSON object.
json parseAuditRow(sqlite3_stmt* st) {
    json row;
    row["id"] = sqlite3_column_int64(st, 0);
    row["ts_unix_ms"] = sqlite3_column_int64(st, 1);
    row["reader_id"] = sqlite3_column_int(st, 2);
    row["door_id"] = sqlite3_column_int(st, 3);
    row["seq"] = sqlite3_column_int64(st, 4);
    row["allow"] = (sqlite3_column_int(st, 5) != 0);

    const unsigned char* reason = sqlite3_column_text(st, 6);
    row["reason"] = reason ? reinterpret_cast<const char*>(reason) : "";

    const unsigned char* ch = sqlite3_column_text(st, 7);
    const unsigned char* act = sqlite3_column_text(st, 8);
    row["card_hmac"] = ch ? reinterpret_cast<const char*>(ch) : "";
    row["action"] = act ? reinterpret_cast<const char*>(act) : "";

    return row;
}

}  // namespace

ServiceResult listAuditLog(AppState& app, int limit, int offset) {
    std::lock_guard<std::mutex> lk(app.m);
    sqlite3* db = app.store->dbHandle();

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, kAuditSelectSql, -1, &st, nullptr) != SQLITE_OK) {
        return errorResult("prepare failed", kHttpServerError);
    }
    sqlite3_bind_int(st, 1, limit);
    sqlite3_bind_int(st, 2, offset);

    json out;
    out["audit"] = json::array();
    while (sqlite3_step(st) == SQLITE_ROW) {
        out["audit"].push_back(parseAuditRow(st));
    }
    sqlite3_finalize(st);

    return okResult(out);
}

ServiceResult verifyAuditChain(AppState& app) {
    std::lock_guard<std::mutex> lk(app.m);

    const auto auditKey = app.keyManager.deriveAuditHmacKey();
    access_storage::SqliteAuditLog::Hash32 h{};
    std::copy(auditKey.begin(), auditKey.end(), h.begin());

    auto vr = access_storage::verifyAuditChain(app.store->dbHandle(), h);

    return okResult({{"ok", vr.ok}, {"error", vr.error}});
}

}  // namespace admin::service
