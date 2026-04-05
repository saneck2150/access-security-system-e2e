#include "access_core/frame_decryptor.hpp"

#include <chrono>

namespace access_core {

FrameDecryptor::FrameDecryptor(crypto_lib::aead::SecureAead& aead, DecryptorConfig config)
    : _aead(aead), _config(config) {}

DecryptResult FrameDecryptor::decrypt(const protocol::frame::Frame& frame) {
    DecryptResult result;

    try {
        result.plaintext = decryptFrame(frame);
    } catch (...) {
        result.success = false;
        result.error = "decrypt_failed";
        return result;
    }

    if (auto error = checkTimestamp(frame.header.ts_unix_ms)) {
        result.success = false;
        result.error = *error;
        return result;
    }

    result.success = true;
    return result;
}

std::vector<uint8_t> FrameDecryptor::decryptFrame(const protocol::frame::Frame& frame) {
    std::vector<uint8_t> aadVec;
    std::span<const uint8_t> aad{};
    if (_config.aadMode != "none") {
        aadVec = frame.header.to_bytes();
        aad = std::span<const uint8_t>(aadVec.data(), aadVec.size());
    }

    crypto_lib::aead::Tag tag{};
    tag.v = frame.tag.v;

    return _aead.openWithNonce(frame.ct, tag, aad, frame.header.nonce);
}

std::optional<std::string> FrameDecryptor::checkTimestamp(uint64_t frameTimestamp) const {
    if (_config.maxSkewMs == 0) {
        return std::nullopt;
    }

    const uint64_t now = nowUnixMs();
    const uint64_t diff = (now >= frameTimestamp) ? (now - frameTimestamp) : (frameTimestamp - now);

    if (diff > _config.maxSkewMs) {
        return (now >= frameTimestamp) ? "too_old" : "too_future";
    }
    return std::nullopt;
}

uint64_t FrameDecryptor::nowUnixMs() const {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

}  // namespace access_core
