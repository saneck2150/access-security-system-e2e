#pragma once
#include "access_decision/access_store.hpp"
#include "access_decision/audit.hpp"
#include "access_decision/card_id_hasher.hpp"
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
    std::string reason;  // "ok" | "parse_error" | "replay" | "decrypt_failed" | "bad_payload" |
                         // "unknown_card" | "forbidden" | "bad_action"
};

class DecisionEngine {
  public:
    DecisionEngine(const access_decision::IAccessStore* store, access_decision::CardIdHasher hasher,
                   IAuditLog* audit)
        : _store(store), _hasher(std::move(hasher)), _audit(audit) {}

    DecisionResult handle_frame_bytes(
        std::span<const uint8_t> frame_bytes, crypto_lib::aead::SecureAead& server_aead,
        std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replay_by_reader);

  private:
    const access_decision::IAccessStore* _store = nullptr;
    access_decision::CardIdHasher _hasher;
    IAuditLog* _audit = nullptr;
};

}  // namespace access_decision
