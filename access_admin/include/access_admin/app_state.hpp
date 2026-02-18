#pragma once

#include <access_decision/engine.hpp>
#include <access_storage/sqlite_access_store.hpp>
#include <access_storage/sqlite_audit_log.hpp>
#include <config_loader/config.hpp>
#include <key_manager/key_manager.hpp>
#include <runtime_events/event_bus.hpp>

#include <mutex>
#include <memory>
#include <string>
#include <unordered_map>

namespace admin {

struct AppState {
    std::mutex m;

    config_loader::Config cfg{};
    std::string dbPath;

    runtime_events::EventBus events;
    key_manager::KeyManager keyManager;

    std::unique_ptr<access_storage::SqliteAccessStore> store;
    std::unique_ptr<access_storage::SqliteAuditLog> audit;
    std::unique_ptr<access_decision::DecisionEngine> engine;

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> replayByReader;

    AppState(config_loader::Config c, std::string db, key_manager::KeyManager km);

    void openOrCreate();
    bool importDbFile(const std::string& uploadedPath, std::string& error);
};

} // namespace admin
