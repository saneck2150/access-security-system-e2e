#include "access_core/handle_frame.hpp"

#include <crypto_lib/secure_aead.hpp>

namespace access_core {

FrameHandler::FrameHandler(const key_manager::KeyManager& keyManager,
                           ReplayWindowMap& replayWindows,
                           FrameHandlerConfig config)
    : _keyManager(keyManager), _replayWindows(replayWindows), _config(config) {}

HandleResult FrameHandler::handle(std::span<const uint8_t> frameBytes) {
    protocol::frame::Frame frame;
    try {
        frame = protocol::frame::parseFrame(frameBytes, _config.maxCtLen);
    } catch (...) {
        return makeError("parse_error");
    }

    protocol::replay::ReplayWindow* window = nullptr;
    if (_config.antiReplayEnabled) {
        window = getOrCreateWindow(frame.header.reader_id);
        if (isReplay(window, frame.header.seq)) {
            return makeError("replay", frame.header);
        }
    }

    return tryDecrypt(frame, window);
}

HandleResult FrameHandler::makeError(const std::string& reason,
                                     const protocol::packet::Header& header) const {
    return HandleResult{.allow = false, .reason = reason, .plaintext = {}, .header = header};
}

protocol::replay::ReplayWindow* FrameHandler::getOrCreateWindow(uint32_t readerId) {
    const size_t windowSize = (_config.replayWindowSize == 0) ? 1 : _config.replayWindowSize;
    auto& window = _replayWindows.try_emplace(readerId, protocol::replay::ReplayWindow(windowSize))
                       .first->second;
    return &window;
}

bool FrameHandler::isReplay(protocol::replay::ReplayWindow* window, uint64_t seq) const {
    return window && window->contains(seq);
}

HandleResult FrameHandler::tryDecrypt(const protocol::frame::Frame& frame,
                                      protocol::replay::ReplayWindow* window) {
    if (!_keyManager.isAcceptedKeyVersion(frame.header.key_version)) {
        return makeError("bad_key_version", frame.header);
    }

    try {
        const auto aeadKey = _keyManager.deriveAeadKey(frame.header.reader_id, frame.header.key_version);
        crypto_lib::aead::SecureAead aead(aeadKey);
        access_core::FrameDecryptor decryptor(aead, access_core::DecryptorConfig{.maxSkewMs = _config.maxSkewMs});

        auto dec = decryptor.decrypt(frame);

        if (!dec.success) {
            return makeError(dec.error, frame.header);
        }

        if (_config.antiReplayEnabled && window) {
            window->remember(frame.header.seq);
        }

        return HandleResult{
            .allow = true,
            .reason = "ok",
            .plaintext = std::move(dec.plaintext),
            .header = frame.header
        };
    } catch (...) {
        return makeError("decrypt_failed", frame.header);
    }
}

}  // namespace access_core
