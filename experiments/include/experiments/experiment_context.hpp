#pragma once

//! @file experiment_context.hpp
//! Self-contained engine pipeline for one experiment profile run.

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <access_core/protocol_anomaly_detector.hpp>
#include <access_decision/audit.hpp>
#include <access_decision/card_id_hasher.hpp>
#include <access_decision/engine.hpp>
#include <access_storage/sqlite_access_store.hpp>
#include <key_manager/key_manager.hpp>
#include <protocol_lib/replay_window.hpp>
#include <runtime_events/event_bus.hpp>

#include "experiments/frame_factory.hpp"

namespace experiments {

//! Encapsulates the full DecisionEngine pipeline for one profile.
//! No HTTP, no config files — everything is wired programmatically.
class ExperimentContext {
  public:
    //! @param [in] profile    Profile configuration.
    //! @param [in] masterKey  Fixed 32-byte master key.
    //! @param [in] dbPath     Temp SQLite file path.
    //! @param [in] readerId   Reader to register.
    //! @param [in] doorId     Door to register.
    //! @param [in] keyVersion Key version.
    //! @param [in] cardIds    Card UIDs to register (all get "employee" role).
    ExperimentContext(const ProfileConfig& profile,
        const key_manager::KeyManager::MasterKey& masterKey,
        const std::string& dbPath,
        uint32_t readerId, uint32_t doorId,
        uint32_t keyVersion,
        const std::vector<std::string>& cardIds);

    //! Processes a frame through the full engine pipeline.
    //! @return Decision result (allow/deny + reason).
    access_decision::DecisionResult processFrame(std::span<const uint8_t> frameBytes);

    //! Returns true if the reader is currently quarantined (R2 only).
    bool isQuarantined(uint32_t readerId) const;

    //! Returns anomaly type string if quarantined, empty otherwise.
    std::string quarantineAnomalyType(uint32_t readerId) const;

    //! Resets state between attack iterations.
    //! Clears replay windows, unquarantines reader.
    void resetState(uint32_t readerId);

    //! Registers an additional door for a reader (bypasses binding check for that door).
    void allowDoorForReader(uint32_t readerId, uint32_t doorId);

    //! Provides access to KeyManager for FrameFactory creation.
    const key_manager::KeyManager& keyManager() const { return _km; }

  private:
    key_manager::KeyManager _km;
    std::unique_ptr<access_storage::SqliteAccessStore> _store;
    access_decision::CardIdHasher _hasher;
    access_decision::InMemoryAuditLog _audit;
    runtime_events::EventBus _events;
    access_core::ProtocolAnomalyDetector _detector;
    std::unique_ptr<access_decision::DecisionEngine> _engine;
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> _replayWindows;

    access_core::FrameHandlerConfig buildFhConfig(const ProfileConfig& profile);
};

}  // namespace experiments
