#pragma once

//! @file app_state.hpp
//! Application state container for the admin server.

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <httplib.h>
#include <access_core/protocol_anomaly_detector.hpp>
#include <access_decision/engine.hpp>
#include <access_storage/sqlite_access_store.hpp>
#include <access_storage/sqlite_audit_log.hpp>
#include <config_loader/config.hpp>
#include <key_manager/key_manager.hpp>
#include <runtime_events/event_bus.hpp>

namespace admin {

//! Central application state holding all server components.
//! Thread-safe via mutex for concurrent HTTP request handling.
struct AppState {
    std::mutex m;  //! Protects all mutable state (admin API on port 8080).
    std::mutex engineMutex;  //! Protects DecisionEngine (decision endpoint on port 8081).

    //! Persistent HTTP client for decision service (port 8081, keep-alive).
    std::unique_ptr<httplib::Client> decisionClient;

    config_loader::Config cfg{};  //! Server configuration.
    std::string dbPath;           //! SQLite database path.

    runtime_events::EventBus events;                   //! Real-time event stream.
    key_manager::KeyManager keyManager;                //! Cryptographic key manager.
    access_core::ProtocolAnomalyDetector anomalyDetector;  //! R2 runtime anomaly detector.

    std::unique_ptr<access_storage::SqliteAccessStore> store;  //! Access policy store.
    std::unique_ptr<access_storage::SqliteAuditLog> audit;     //! Audit log.
    std::unique_ptr<access_decision::DecisionEngine> engine;   //! Decision engine.

    //! Replay windows per reader for anti-replay.
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> replayByReader;
    //! Last sequence number per reader for hardware scanner.
    std::unordered_map<uint32_t, uint64_t> lastSeqByReader;


    //! Constructs AppState with configuration.
    //! @param [in] c   Server configuration.
    //! @param [in] db  SQLite database path.
    //! @param [in] km  Key manager instance.
    AppState(config_loader::Config c, std::string db, key_manager::KeyManager km);

    //! Opens or creates the database and initializes all components.
    void openOrCreate();

    //! Imports a database file after verification.
    //! @param [in]  uploadedPath Path to uploaded DB file.
    //! @param [out] error        Error message if failed.
    //! @return True if import succeeded.
    bool importDbFile(const std::string& uploadedPath, std::string& error);
};

}  // namespace admin
