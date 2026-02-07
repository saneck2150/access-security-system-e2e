#include "access_decision/engine.hpp"
#include "access_decision/payload.hpp"

#include <string_view>

namespace access_decision {

DecisionResult DecisionEngine::handle_frame_bytes(
    std::span<const uint8_t> frame_bytes, crypto_lib::aead::SecureAead& server_aead,
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replay_by_reader) {
    const auto hf = access_core::handle_frame(frame_bytes, server_aead, replay_by_reader);

    DecisionResult out;
    if (!hf.allow) {
        out.allow = false;
        out.reason = hf.reason;

        if (_audit) {
            AuditEvent ev;
            ev.ts_unix_ms = hf.header.ts_unix_ms;
            ev.reader_id = hf.header.reader_id;
            ev.door_id = hf.header.door_id;
            ev.seq = hf.header.seq;
            ev.allow = false;
            ev.reason = out.reason;
            _audit->append(std::move(ev));
        }
        return out;
    }

    std::string_view sv(reinterpret_cast<const char*>(hf.plaintext.data()), hf.plaintext.size());

    AccessRequest req;
    try {
        req = parse_access_request_json(sv);
    } catch (...) {
        out.allow = false;
        out.reason = "bad_payload";

        if (_audit) {
            AuditEvent ev;
            ev.ts_unix_ms = hf.header.ts_unix_ms;
            ev.reader_id = hf.header.reader_id;
            ev.door_id = hf.header.door_id;
            ev.seq = hf.header.seq;
            ev.allow = false;
            ev.reason = out.reason;
            _audit->append(std::move(ev));
        }
        return out;
    }

    if (req.action != "open") {
        out.allow = false;
        out.reason = "bad_action";
    } else if (!_store) {
        out.allow = false;
        out.reason = "no_store";
    } else {
        const auto card_hmac = _hasher.hmac_hex(req.card_id);
        const auto role_opt = _store->role_for_card_hmac(card_hmac);

        if (!role_opt.has_value()) {
            out.allow = false;
            out.reason = "unknown_card";
        } else if (!_store->is_allowed(hf.header.door_id, *role_opt)) {
            out.allow = false;
            out.reason = "forbidden";
        } else {
            out.allow = true;
            out.reason = "ok";
        }

        if (_audit) {
            AuditEvent ev;
            ev.ts_unix_ms = hf.header.ts_unix_ms;
            ev.reader_id = hf.header.reader_id;
            ev.door_id = hf.header.door_id;
            ev.seq = hf.header.seq;
            ev.allow = out.allow;
            ev.reason = out.reason;
            ev.card_id = card_hmac;
            ev.action = req.action;
            _audit->append(std::move(ev));
        }
    }
    return out;
}

}  // namespace access_decision
