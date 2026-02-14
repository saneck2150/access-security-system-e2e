#pragma once

#include "access_decision/access_store.hpp"
#include "access_decision/audit.hpp"
#include "access_decision/card_id_hasher.hpp"
#include "access_decision/payload.hpp"
#include "access_decision/policy.hpp"

#include <access_core/handle_frame.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/replay_window.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace access_decision {

struct DecisionResult {
    bool allow = false;
    std::string reason; // "ok" | "parse_error" | "replay" | "decrypt_failed" | "bad_payload" |
                        // "unknown_card" | "forbidden" | "bad_action"
};

class DecisionEngine {
  public:
    DecisionEngine(const IAccessStore* store, CardIdHasher hasher, IAuditLog* audit,
                   access_core::FrameHandlerConfig frameHandlerCfg = {});

    DecisionResult handleFrameBytes(
        std::span<const uint8_t> frameBytes, crypto_lib::aead::SecureAead& serverAead,
        std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replayByReader);

  private:
    // dependencies
    const IAccessStore* _store = nullptr;
    CardIdHasher _hasher;
    IAuditLog* _audit = nullptr;
    access_core::FrameHandlerConfig _frameHandlerCfg{};

    // helpers
    void logAuditEvent(const protocol::packet::Header& header, bool allow,
                       const std::string& reason, const std::string& cardId = "",
                       const std::string& action = "");

    DecisionResult createDeniedResult(const std::string& reason);

    DecisionResult checkAccessPolicy(const access_core::HandleResult& frameResult,
                                     const AccessRequest& request);
};

} // namespace access_decision
