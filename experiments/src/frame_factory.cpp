#include "experiments/frame_factory.hpp"

#include <cstring>
#include <stdexcept>

#include <nlohmann/json.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

namespace experiments {

namespace {

//! Frame byte offsets (magic=4, version=1, then header fields).
constexpr size_t kOffsetReaderId = 5;
constexpr size_t kOffsetDoorId = 9;
constexpr size_t kOffsetSeq = 21;
constexpr size_t kOffsetCtLen = 57;
constexpr size_t kOffsetCt = 61;

void putLe32(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>(v);
    dst[1] = static_cast<uint8_t>(v >> 8);
    dst[2] = static_cast<uint8_t>(v >> 16);
    dst[3] = static_cast<uint8_t>(v >> 24);
}

void putLe64(uint8_t* dst, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        dst[i] = static_cast<uint8_t>(v >> (i * 8));
    }
}

uint32_t readLe32(const uint8_t* src) {
    return static_cast<uint32_t>(src[0]) | (static_cast<uint32_t>(src[1]) << 8) |
           (static_cast<uint32_t>(src[2]) << 16) | (static_cast<uint32_t>(src[3]) << 24);
}

}  // namespace

FrameFactory::FrameFactory(const key_manager::KeyManager& km,
    const ProfileConfig& profile,
    std::unique_ptr<crypto_lib::nonce::INonceGenerator> nonceGen)
    : _km(km), _profile(profile), _nonceGen(std::move(nonceGen)) {}

crypto_lib::aead::CipherMode FrameFactory::cipherModeEnum() const {
    return (_profile.cipherMode == "chacha20")
               ? crypto_lib::aead::CipherMode::ChaCha20Poly1305
               : crypto_lib::aead::CipherMode::XChaCha20Poly1305;
}

std::vector<uint8_t> FrameFactory::buildFrame(uint32_t readerId, uint32_t doorId,
    uint64_t seq, uint32_t keyVersion, uint64_t tsUnixMs,
    std::string_view cardId, std::string_view action) {
    // 1. Build JSON payload.
    nlohmann::json j;
    j["card_id"] = cardId;
    j["action"] = action;
    const std::string payloadText = j.dump();

    // 2. Derive AEAD key.
    const auto cm = cipherModeEnum();
    crypto_lib::aead::AeadKey aeadKey;
    if (_profile.keyDerivationMode == "direct") {
        aeadKey = _km.masterAsAeadKey();
    } else {
        aeadKey = _km.deriveAeadKey(readerId, keyVersion);
    }
    crypto_lib::aead::SecureAead aead(aeadKey, cm);

    // 3. Build nonce context (header with nonce zeroed).
    protocol::packet::Header ctxHeader;
    ctxHeader.reader_id = readerId;
    ctxHeader.door_id = doorId;
    ctxHeader.ts_unix_ms = tsUnixMs;
    ctxHeader.seq = seq;
    ctxHeader.key_version = keyVersion;
    ctxHeader.nonce = {};  // Zeroed — nonce not part of its own derivation.
    const auto context = ctxHeader.to_bytes();

    // 4. Generate nonce.
    const auto nonce = _nonceGen->generate(
        std::span<const uint8_t>(context.data(), context.size()), seq);

    // 5. Build real header with nonce.
    protocol::packet::Header header = ctxHeader;
    header.nonce = nonce;

    // 6. Encrypt with AAD.
    std::vector<uint8_t> aadVec;
    std::span<const uint8_t> aad{};
    if (_profile.aadMode != "none") {
        aadVec = header.to_bytes();
        aad = std::span<const uint8_t>(aadVec.data(), aadVec.size());
    }
    const auto pt = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(payloadText.data()), payloadText.size());
    const auto cipher = aead.sealWithNonce(pt, aad, nonce);

    // 7. Assemble and serialize frame.
    protocol::frame::Frame f;
    f.header = header;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    return protocol::frame::serialize(f);
}

std::vector<uint8_t> FrameFactory::tamperDoorId(
    const std::vector<uint8_t>& frameBytes, uint32_t newDoorId) {
    auto copy = frameBytes;
    if (copy.size() < kOffsetDoorId + 4) {
        throw std::runtime_error("tamperDoorId: frame too short");
    }
    putLe32(&copy[kOffsetDoorId], newDoorId);
    return copy;
}

std::vector<uint8_t> FrameFactory::tamperReaderId(
    const std::vector<uint8_t>& frameBytes, uint32_t newReaderId) {
    auto copy = frameBytes;
    if (copy.size() < kOffsetReaderId + 4) {
        throw std::runtime_error("tamperReaderId: frame too short");
    }
    putLe32(&copy[kOffsetReaderId], newReaderId);
    return copy;
}

std::vector<uint8_t> FrameFactory::tamperCiphertext(
    const std::vector<uint8_t>& frameBytes) {
    auto copy = frameBytes;
    if (copy.size() < kOffsetCt + 1 + 16) {
        throw std::runtime_error("tamperCiphertext: frame too short");
    }
    const uint32_t ctLen = readLe32(&copy[kOffsetCtLen]);
    for (uint32_t i = 0; i < ctLen && (kOffsetCt + i) < copy.size() - 16; ++i) {
        copy[kOffsetCt + i] ^= 0xFF;
    }
    return copy;
}

std::vector<uint8_t> FrameFactory::tamperSeq(
    const std::vector<uint8_t>& frameBytes, uint64_t newSeq) {
    auto copy = frameBytes;
    if (copy.size() < kOffsetSeq + 8) {
        throw std::runtime_error("tamperSeq: frame too short");
    }
    putLe64(&copy[kOffsetSeq], newSeq);
    return copy;
}

}  // namespace experiments
