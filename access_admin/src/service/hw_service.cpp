#include <mutex>

#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <access_admin/service/hw_service.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>
#include <sodium.h>

namespace admin::service {

namespace {

//! @return Serialized JSON string.
std::string buildPayloadJson(std::string_view uid, std::string_view action) {
    json payload;
    payload["card_id"] = std::string(uid);
    payload["action"] = std::string(action);
    return payload.dump();
}

protocol::packet::Header buildPacketHeader(uint32_t reader_id,
    uint32_t door_id,
    uint64_t seq,
    uint32_t key_version,
    uint64_t ts_unix_ms,
    const std::array<uint8_t, 24>& nonce) {
    protocol::packet::Header h;
    h.reader_id = reader_id;
    h.door_id = door_id;
    h.ts_unix_ms = ts_unix_ms;
    h.seq = seq;
    h.key_version = key_version;
    h.nonce = nonce;
    return h;
}

//! Encrypts payload and serializes frame.
std::vector<uint8_t> encryptAndSerialize(crypto_lib::aead::SecureAead& aead,
    const protocol::packet::Header& header,
    const std::string& payload_text,
    uint64_t seq,
    std::string_view aadMode) {
    std::vector<uint8_t> aadVec;
    std::span<const uint8_t> aad{};
    if (aadMode != "none") {
        aadVec = header.to_bytes();
        aad = std::span<const uint8_t>(aadVec.data(), aadVec.size());
    }
    const std::span<const uint8_t> pt(
        reinterpret_cast<const uint8_t*>(payload_text.data()), payload_text.size());

    const auto c = aead.sealWithSeq(pt, aad, seq);

    protocol::frame::Frame f;
    f.header = header;
    f.ct = c.ct;
    f.tag.v = c.tag.v;

    return protocol::frame::serialize(f);
}

//! Builds an encrypted frame from hardware UID request.
std::vector<uint8_t> buildEncryptedFrameBytes(const key_manager::KeyManager& km,
    uint32_t reader_id,
    uint32_t door_id,
    uint64_t seq,
    uint32_t key_version,
    uint64_t ts_unix_ms,
    std::string_view uid,
    std::string_view action,
    std::string_view keyDerivationMode,
    std::string_view aadMode,
    std::string_view cipherMode) {
    const std::string payloadText = buildPayloadJson(uid, action);

    const auto aeadKey = (keyDerivationMode == "direct") ? km.masterAsAeadKey()
                                                         : km.deriveAeadKey(reader_id, key_version);
    const auto cm = (cipherMode == "chacha20") ? crypto_lib::aead::CipherMode::ChaCha20Poly1305
                                               : crypto_lib::aead::CipherMode::XChaCha20Poly1305;
    crypto_lib::aead::SecureAead aead(aeadKey, cm);

    const auto header =
        buildPacketHeader(reader_id, door_id, seq, key_version, ts_unix_ms, aead.deriveNonce(seq));

    return encryptAndSerialize(aead, header, payloadText, seq, aadMode);
}

//! Pushes hardware event to event bus.
void pushHwEvent(AppState& app,
    const std::string& message,
    uint32_t reader_id,
    uint32_t door_id,
    uint64_t seq = 0) {
    app.events.push({.ts_unix_ms = nowUnixMs(),
        .kind = "hw",
        .message = message,
        .reader_id = reader_id,
        .door_id = door_id,
        .seq = seq});
}

//! Builds JSON response for hardware endpoint.
json buildHwResponse(bool allow,
    const std::string& reason,
    uint32_t reader_id,
    uint32_t door_id,
    uint64_t seq,
    uint32_t key_version) {
    json out;
    out["allow"] = allow;
    out["reason"] = reason;
    out["reader_id"] = reader_id;
    out["door_id"] = door_id;
    out["seq"] = seq;
    out["key_version"] = key_version;
    return out;
}

//! Converts hex character to nibble value.
uint8_t hexNibble(char c) {
    if (c >= '0' && c <= '9')
        return uint8_t(c - '0');
    if (c >= 'a' && c <= 'f')
        return uint8_t(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F')
        return uint8_t(10 + (c - 'A'));
    return 0;
}

//! Decodes hex string to bytes.
std::vector<uint8_t> hexToBytesLoose(const std::string& hex) {
    if (hex.size() % 2 != 0)
        return {};
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = uint8_t((hexNibble(hex[i * 2]) << 4) | hexNibble(hex[i * 2 + 1]));
    }
    return out;
}

//! Parses HMAC key from hex string.
bool parseHmacKey(const std::string& hex, std::vector<uint8_t>& key, std::string& err) {
    key = hexToBytesLoose(hex);
    if (key.size() != crypto_auth_hmacsha256_KEYBYTES) {
        err = "bad_hw_secret_len";
        return false;
    }
    return true;
}

//! Parses signature from hex string.
bool parseSignature(const std::string& hex, std::vector<uint8_t>& sig, std::string& err) {
    sig = hexToBytesLoose(hex);
    if (sig.size() != crypto_auth_hmacsha256_BYTES) {
        err = "bad_signature_len";
        return false;
    }
    return true;
}

//! Computes HMAC-SHA256 and compares with expected signature.
bool verifyHmac(const std::string& msg,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& expected_sig) {
    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256(mac,
        reinterpret_cast<const unsigned char*>(msg.data()),
        msg.size(),
        reinterpret_cast<const unsigned char*>(key.data()));
    return sodium_memcmp(mac, expected_sig.data(), crypto_auth_hmacsha256_BYTES) == 0;
}

}  // namespace

bool verifyHwSignature(const std::string& signature_hex,
    const std::string& body,
    const std::string& hw_secret_hex,
    std::string& err) {
    if (hw_secret_hex.empty()) {
        err = "misconfigured";
        return false;  // HMAC secret not set - server misconfigured
    }
    if (sodium_init() < 0) {
        err = "sodium_init_failed";
        return false;
    }
    if (signature_hex.empty()) {
        err = "missing_signature";
        return false;
    }

    std::vector<uint8_t> key;
    if (!parseHmacKey(hw_secret_hex, key, err)) {
        return false;
    }

    std::vector<uint8_t> sig;
    if (!parseSignature(signature_hex, sig, err)) {
        return false;
    }

    const std::string msg = std::string("POST /api/hw/uid\n") + body;
    if (!verifyHmac(msg, key, sig)) {
        err = "bad_signature";
        return false;
    }
    return true;
}

bool parseHwUidRequest(const json& j, HwUidRequest& req) {
    try {
        if (j.contains("uid")) {
            req.uid = j.at("uid").get<std::string>();
        } else {
            req.uid = j.at("card_id").get<std::string>();
        }
        req.reader_id = j.at("reader_id").get<uint32_t>();
        req.door_id = j.at("door_id").get<uint32_t>();
        req.hw_seq = j.at("hw_seq").get<uint64_t>();
        req.action = j.value("action", std::string("open"));
        return true;
    } catch (...) {
        return false;
    }
}

ServiceResult processHwUid(AppState& app, const HwUidRequest& req) {
    const uint64_t ts = nowUnixMs();

    std::lock_guard<std::mutex> lk(app.m);

    const uint32_t kv = app.store->currentKeyVersionForReader(req.reader_id);
    if (kv == 0) {
        pushHwEvent(app, "hw uid: unknown_reader", req.reader_id, req.door_id);
        return okResult({{"allow", false}, {"reason", "unknown_reader"}});
    }

    // Use hw_seq from hardware (monotonic counter) for replay protection
    const uint64_t seq = req.hw_seq;
    pushHwEvent(app, "uid=" + req.uid, req.reader_id, req.door_id, seq);

    const auto frameBytes = buildEncryptedFrameBytes(app.keyManager,
        req.reader_id,
        req.door_id,
        seq,
        kv,
        ts,
        req.uid,
        req.action,
        app.cfg.experiment.keyDerivationMode,
        app.cfg.experiment.aadMode,
        app.cfg.experiment.cipherMode);

    const auto r = app.engine->handleFrameBytes(frameBytes, app.replayByReader);

    return okResult(buildHwResponse(r.allow, r.reason, req.reader_id, req.door_id, seq, kv));
}

}  // namespace admin::service
