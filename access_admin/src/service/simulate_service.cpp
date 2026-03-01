#include <mutex>

#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <access_admin/service/simulate_service.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>

namespace admin::service {

namespace {

//! Builds an encrypted frame for simulation.
std::vector<uint8_t> buildFrameBytes(const key_manager::KeyManager& km,
                                     uint32_t reader_id,
                                     uint32_t door_id,
                                     uint64_t seq,
                                     uint32_t key_version,
                                     uint64_t ts_unix_ms,
                                     std::string_view json_payload) {
    protocol::packet::Header h;
    h.reader_id = reader_id;
    h.door_id = door_id;
    h.ts_unix_ms = ts_unix_ms;
    h.seq = seq;
    h.key_version = key_version;

    crypto_lib::aead::SecureAead sender(km.deriveAeadKey(reader_id, key_version));
    h.nonce = sender.deriveNonce(seq);

    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(json_payload.data()),
                                 json_payload.size()),
        aad,
        seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    return protocol::frame::serialize(f);
}

}  // namespace

bool parseSimulateScanRequest(const json& j, SimulateScanRequest& req) {
    try {
        req.card_id = j.at("card_id").get<std::string>();
        req.reader_id = j.at("reader_id").get<uint32_t>();
        req.door_id = j.at("door_id").get<uint32_t>();
        req.action = j.value("action", std::string("open"));

        if (j.contains("key_version")) {
            req.key_version = j.at("key_version").get<uint32_t>();
        }
        if (j.contains("ts_unix_ms")) {
            req.ts_unix_ms = j.at("ts_unix_ms").get<uint64_t>();
        }
        if (j.contains("seq")) {
            req.seq = j.at("seq").get<uint64_t>();
        }
        return true;
    } catch (...) {
        return false;
    }
}

ServiceResult simulateScan(AppState& app, const SimulateScanRequest& req) {
    std::lock_guard<std::mutex> lk(app.m);

    const uint32_t currentKv = app.store->currentKeyVersionForReader(req.reader_id);
    if (currentKv == 0) {
        app.events.push({.ts_unix_ms = nowUnixMs(),
                         .kind = "sim",
                         .message = "simulate_scan: unknown_reader",
                         .reader_id = req.reader_id,
                         .door_id = req.door_id});
        return errorResult("unknown_reader", kHttpBadRequest);
    }

    const uint32_t kv = req.key_version.value_or(currentKv);
    const uint64_t ts = req.ts_unix_ms.value_or(nowUnixMs());

    uint64_t seq;
    if (req.seq.has_value()) {
        seq = req.seq.value();
    } else {
        auto& last = app.lastSeqByReader[req.reader_id];
        last += 1;
        seq = last;
    }

    json payload;
    payload["card_id"] = req.card_id;
    payload["action"] = req.action;

    app.events.push({.ts_unix_ms = nowUnixMs(),
                     .kind = "sim",
                     .message = "simulate_scan: build+send",
                     .reader_id = req.reader_id,
                     .door_id = req.door_id,
                     .seq = seq});

    const auto frameBytes =
        buildFrameBytes(app.keyManager, req.reader_id, req.door_id, seq, kv, ts, payload.dump());
    const auto dec = app.engine->handleFrameBytes(frameBytes, app.replayByReader);

    json out;
    out["allow"] = dec.allow;
    out["reason"] = dec.reason;
    out["reader_id"] = req.reader_id;
    out["door_id"] = req.door_id;
    out["seq"] = seq;
    out["key_version"] = kv;
    out["ts_unix_ms"] = ts;
    out["payload"] = payload;
    out["frame_len"] = frameBytes.size();
    out["frame_hex"] = bytesToHex(frameBytes);

    return okResult(out);
}

}  // namespace admin::service
