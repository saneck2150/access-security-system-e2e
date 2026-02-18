#pragma once

#include "access_decision/access_store.hpp"
#include "access_decision/audit.hpp"
#include "access_decision/card_id_hasher.hpp"
#include "access_decision/payload.hpp"
#include "access_decision/policy.hpp"

#include <access_core/handle_frame.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <key_manager/key_manager.hpp>
#include <protocol_lib/replay_window.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace runtime_events { class EventBus; }

namespace access_decision {

struct DecisionResult {
    bool allow = false;
    std::string reason; // "ok" | "parse_error" | "replay" | "decrypt_failed" | "bad_payload" |
                        // "unknown_card" | "forbidden" | "bad_action"
};

class DecisionEngine {
  public:
    DecisionEngine(const IAccessStore* store, CardIdHasher hasher, IAuditLog* audit,
                  const key_manager::KeyManager& keyManager,
                  access_core::FrameHandlerConfig frameHandlerCfg = {},
                  runtime_events::EventBus* events = nullptr);

    DecisionResult handleFrameBytes(
        std::span<const uint8_t> frameBytes,
        std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replayByReader);

  private:
    const IAccessStore* _store = nullptr;
    CardIdHasher _hasher;
    IAuditLog* _audit = nullptr;
    runtime_events::EventBus* _events = nullptr;

    const key_manager::KeyManager& _keyManager;
    access_core::FrameHandlerConfig _frameHandlerCfg{};

    void logAuditEvent(const protocol::packet::Header& header, bool allow,
                       const std::string& reason, const std::string& cardId = "",
                       const std::string& action = "");

    DecisionResult createDeniedResult(const std::string& reason);

    DecisionResult checkAccessPolicy(const access_core::HandleResult& frameResult,
                                     const AccessRequest& request);
};

} // namespace access_decision
