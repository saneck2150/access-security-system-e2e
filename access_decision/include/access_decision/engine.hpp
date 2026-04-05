#pragma once

//! @file engine.hpp
//! Core access decision engine that orchestrates frame handling and policy
//! enforcement.

#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <access_core/handle_frame.hpp>
#include <access_core/protocol_anomaly_detector.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <key_manager/key_manager.hpp>
#include <protocol_lib/replay_window.hpp>

#include "access_decision/access_store.hpp"
#include "access_decision/audit.hpp"
#include "access_decision/card_id_hasher.hpp"
#include "access_decision/payload.hpp"
#include "access_decision/policy.hpp"

namespace runtime_events {
class EventBus;
}

namespace access_decision {

//! Result of an access decision check.
struct DecisionResult {
    //! True if access is granted, false if denied.
    bool allow = false;

    //! Machine-readable reason code.
    //! Values: "ok", "parse_error", "replay", "decrypt_failed", "bad_payload",
    //!         "unknown_reader", "unknown_card", "forbidden", "bad_action",
    //!         "no_store".
    std::string reason;
};

//! Core decision engine that processes access requests and enforces policies.
//! Handles frame decryption, policy lookup, and audit logging.
class DecisionEngine {
  public:
    //! Constructs a DecisionEngine with required dependencies.
    //! @param [in] store           Pointer to access policy store (must outlive
    //! engine).
    //! @param [in] hasher          CardIdHasher configured with current pepper
    //! key.
    //! @param [in] audit           Pointer to audit log (may be nullptr to
    //! disable).
    //! @param [in] keyManager      Reference to key manager for key derivation.
    //! @param [in] frameHandlerCfg Configuration for frame handling.
    //! @param [in] events          Optional EventBus for real-time events.
    //! @param [in] detector        Optional R2 anomaly detector (may be nullptr).
    DecisionEngine(const IAccessStore* store,
        CardIdHasher hasher,
        IAuditLog* audit,
        const key_manager::KeyManager& keyManager,
        access_core::FrameHandlerConfig frameHandlerCfg = {},
        runtime_events::EventBus* events = nullptr,
        access_core::ProtocolAnomalyDetector* detector = nullptr);

    //! Processes an encrypted frame and returns an access decision.
    //! @param [in]     frameBytes     Raw encrypted frame bytes from the reader.
    //! @param [in,out] replayByReader Map of replay windows per reader ID.
    //! @return DecisionResult with allow/deny and reason code.
    DecisionResult handleFrameBytes(std::span<const uint8_t> frameBytes,
        std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replayByReader);

  private:
    const IAccessStore* _store = nullptr;
    CardIdHasher _hasher;
    IAuditLog* _audit = nullptr;
    runtime_events::EventBus* _events = nullptr;
    access_core::ProtocolAnomalyDetector* _detector = nullptr;
    const key_manager::KeyManager& _keyManager;
    access_core::FrameHandlerConfig _frameHandlerCfg{};

    //! Logs an audit event for the access decision.
    void logAuditEvent(const protocol::packet::Header& header,
        bool allow,
        const std::string& reason,
        const std::string& cardId = "",
        const std::string& action = "");

    //! Creates a denied DecisionResult with the given reason.
    DecisionResult createDeniedResult(const std::string& reason);

    //! Publishes a frame-received event to the event bus.
    void publishFrameEvent(size_t frameSize);

    //! Publishes a decision event to the event bus.
    void publishDecisionEvent(const access_core::HandleResult& frameResult);

    //! Resolves card ID to HMAC, trying current and previous key versions.
    //! @param [in]  cardId    Plain card identifier.
    //! @param [in]  currentKv Current key version.
    //! @param [out] roleOut   Role if card found.
    //! @return Card HMAC (current or previous version).
    std::string resolveCardHmac(
        const std::string& cardId, uint32_t currentKv, std::optional<std::string>& roleOut);

    //! Checks if a role has access to a door.
    DecisionResult checkRoleAccess(uint32_t doorId, const std::string& role);

    //! Checks access policy after frame validation.
    DecisionResult checkAccessPolicy(
        const access_core::HandleResult& frameResult, const AccessRequest& request);

    //! Publishes an anomaly event to the event bus.
    void publishAnomalyEvent(uint32_t readerId, access_core::AnomalyType type,
        const std::string& detail);
};

}  // namespace access_decision
