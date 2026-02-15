#include "access_core/handle_frame.hpp"

#include <crypto_lib/secure_aead.hpp>

namespace access_core {

FrameHandler::FrameHandler(const key_manager::KeyManager& keyManager,
                           ReplayWindowMap& replayWindows,
                           const access_decision::IAccessStore* store,
                           FrameHandlerConfig config)
    : _keyManager(keyManager),
      _replayWindows(replayWindows),
      _store(store),
      _config(config) {}

/// @todo: split handle into smaller functions and add more specific error reasons
HandleResult FrameHandler::handle(std::span<const uint8_t> frameBytes) {
    protocol::frame::Frame frame;
    try {
        frame = protocol::frame::parseFrame(frameBytes, _config.maxCtLen);
    } catch (...) {
        return makeError("parse_error");
    }

    if (!_store) {
        return makeError("no_store", frame.header);
    }

    const uint32_t currentKeyVersion =
        _store->currentKeyVersionForReader(frame.header.reader_id);
    if (currentKeyVersion == 0) {
        return makeError("unknown_reader", frame.header);
    }

    if (_config.enforceReaderDoorBinding) {
        if (!_store->isReaderAllowedDoor(frame.header.reader_id, frame.header.door_id)) {
            return makeError("reader_door_forbidden", frame.header);
        }
    }

    const uint32_t kv = frame.header.key_version;
    const bool acceptPrev = _config.allowPreviousKeyVersion;
    const bool keyOk =
        (kv == currentKeyVersion) ||
        (acceptPrev && currentKeyVersion > 1 && kv + 1 == currentKeyVersion);
    if (!keyOk) {
        return makeError("bad_key_version", frame.header);
    }

    protocol::replay::ReplayWindow* window = nullptr;
    if (_config.antiReplayEnabled) {
        window = getOrCreateWindow(frame.header.reader_id);
        if (isReplay(window, frame.header.seq)) {
            return makeError("replay", frame.header);
        }
    }

    return tryDecrypt(frame, window, currentKeyVersion);
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
                                      protocol::replay::ReplayWindow* window,
                                      uint32_t /*currentKeyVersion*/) {
    try {
        const auto aeadKey =
            _keyManager.deriveAeadKey(frame.header.reader_id, frame.header.key_version);

        crypto_lib::aead::SecureAead aead(aeadKey);

        access_core::FrameDecryptor decryptor(
            aead, access_core::DecryptorConfig{.maxSkewMs = _config.maxSkewMs});

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

} // namespace access_core
