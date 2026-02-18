#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>

#include <access_storage/audit_verify.hpp>

#include <filesystem>
#include <algorithm>
#include <stdexcept>

/// @todo split into multiple functions
namespace admin {

AppState::AppState(config_loader::Config c, std::string db, key_manager::KeyManager km)
    : cfg(std::move(c)),
      dbPath(std::move(db)),
      events(cfg.admin.maxEvents),
      keyManager(std::move(km)) {}

void AppState::openOrCreate() {
    std::lock_guard<std::mutex> lk(m);

    std::filesystem::create_directories(std::filesystem::path(dbPath).parent_path());

    store = std::make_unique<access_storage::SqliteAccessStore>(dbPath);
    store->initSchema();

    const auto auditKey = keyManager.deriveAuditHmacKey();
    access_storage::SqliteAuditLog::Hash32 h{};
    std::copy(auditKey.begin(), auditKey.end(), h.begin());
    audit = std::make_unique<access_storage::SqliteAuditLog>(store->dbHandle(), h);

    // dummy hasher (DecisionEngine внутри может пересоздавать)
    access_decision::CardIdHasher dummyHasher(
        keyManager.deriveCardPepper(cfg.keyManagement.currentKeyVersion));

    engine = std::make_unique<access_decision::DecisionEngine>(
        store.get(),
        std::move(dummyHasher),
        audit.get(),
        keyManager,
        cfg.frameHandler,
        &events
    );

    events.push({.ts_unix_ms = nowUnixMs(), .kind="admin", .message="storage opened: " + dbPath});
}

bool AppState::importDbFile(const std::string& uploadedPath, std::string& error) {
    if (!sqliteIntegrityOk(uploadedPath, error)) return false;

    sqlite3* db = nullptr;
    if (sqlite3_open(uploadedPath.c_str(), &db) != SQLITE_OK) {
        error = "sqlite_open(uploaded) failed";
        if (db) sqlite3_close(db);
        return false;
    }

    const auto auditKey = keyManager.deriveAuditHmacKey();
    access_storage::SqliteAuditLog::Hash32 h{};
    std::copy(auditKey.begin(), auditKey.end(), h.begin());

    auto vr = access_storage::verifyAuditChain(db, h);
    sqlite3_close(db);

    if (!vr.ok) {
        error = "verifyAuditChain failed: " + vr.error;
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(m);

        store.reset();
        audit.reset();
        engine.reset();

        const std::string bak = dbPath + ".bak";
        std::error_code ec;
        if (std::filesystem::exists(dbPath, ec)) {
            std::filesystem::copy_file(dbPath, bak,
                                       std::filesystem::copy_options::overwrite_existing, ec);
        }

        std::filesystem::copy_file(uploadedPath, dbPath,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            error = "failed to replace db: " + ec.message();
            return false;
        }
    }

    openOrCreate();
    events.push({.ts_unix_ms = nowUnixMs(), .kind="admin", .message="db imported + reopened"});
    return true;
}

} // namespace admin
