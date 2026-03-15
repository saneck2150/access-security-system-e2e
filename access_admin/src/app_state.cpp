#include <algorithm>
#include <filesystem>
#include <stdexcept>

#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <access_storage/audit_verify.hpp>

namespace admin {

namespace {

//! Creates HMAC key array from key manager.
access_storage::SqliteAuditLog::Hash32 deriveAuditHash(const key_manager::KeyManager& km) {
    const auto auditKey = km.deriveAuditHmacKey();
    access_storage::SqliteAuditLog::Hash32 h{};
    std::copy(auditKey.begin(), auditKey.end(), h.begin());
    return h;
}

//! Verifies audit chain integrity of uploaded database.
bool verifyUploadedAuditChain(
    const std::string& path, const key_manager::KeyManager& km, std::string& error) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        error = "sqlite_open(uploaded) failed";
        if (db) {
            sqlite3_close(db);
        }
        return false;
    }
    auto vr = access_storage::verifyAuditChain(db, deriveAuditHash(km));
    sqlite3_close(db);

    if (!vr.ok) {
        error = "verifyAuditChain failed: " + vr.error;
        return false;
    }
    return true;
}

//! Replaces current database with uploaded file.
bool replaceDbFile(const std::string& dbPath, const std::string& uploadedPath, std::string& error) {
    const std::string bak = dbPath + ".bak";
    std::error_code ec;

    if (std::filesystem::exists(dbPath, ec)) {
        std::filesystem::copy_file(
            dbPath, bak, std::filesystem::copy_options::overwrite_existing, ec);
    }

    std::filesystem::copy_file(
        uploadedPath, dbPath, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        error = "failed to replace db: " + ec.message();
        return false;
    }
    return true;
}

}  // namespace

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

    audit = std::make_unique<access_storage::SqliteAuditLog>(
        store->dbHandle(), deriveAuditHash(keyManager), cfg.experiment.auditChainEnabled);

    access_decision::CardIdHasher hasher(
        keyManager.deriveCardPepper(cfg.keyManagement.currentKeyVersion));

    access_core::FrameHandlerConfig fhCfg = cfg.frameHandler;
    fhCfg.keyDerivationMode = cfg.experiment.keyDerivationMode;
    fhCfg.aadMode = cfg.experiment.aadMode;
    fhCfg.pepperMode = cfg.experiment.pepperMode;
    fhCfg.cipherMode = cfg.experiment.cipherMode;

    engine = std::make_unique<access_decision::DecisionEngine>(
        store.get(), std::move(hasher), audit.get(), keyManager, fhCfg, &events);

    events.push(
        {.ts_unix_ms = nowUnixMs(), .kind = "admin", .message = "storage opened: " + dbPath});
}

bool AppState::importDbFile(const std::string& uploadedPath, std::string& error) {
    if (!sqliteIntegrityOk(uploadedPath, error)) {
        return false;
    }
    if (!verifyUploadedAuditChain(uploadedPath, keyManager, error)) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(m);
        store.reset();
        audit.reset();
        engine.reset();

        if (!replaceDbFile(dbPath, uploadedPath, error)) {
            return false;
        }
    }

    openOrCreate();
    events.push({.ts_unix_ms = nowUnixMs(), .kind = "admin", .message = "db imported + reopened"});
    return true;
}

}  // namespace admin
