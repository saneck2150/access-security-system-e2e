#include "access_core/handle_frame.hpp"

namespace access_core {

FrameHandler::FrameHandler(crypto_lib::aead::SecureAead& aead, ReplayWindowMap& replayWindows,
                           FrameHandlerConfig config)
    : _decryptor(aead, DecryptorConfig{.maxSkewMs = config.maxSkewMs}),
      _replayWindows(replayWindows),
      _config(config) {}


HandleResult FrameHandler::handle(std::span<const uint8_t> frameBytes) {
    protocol::frame::Frame frame;
    try {
        frame = protocol::frame::parseFrame(frameBytes, _config.maxCtLen);
    } catch (const std::exception& e) {
        const std::string msg = e.what();
        if (msg.find("ctLen exceeds limit") != std::string::npos) {
            return makeError("frame_too_large");
        }
        return makeError("parse_error");
    }

    protocol::replay::ReplayWindow* window = nullptr;
    if (_config.antiReplayEnabled) {
        window = getOrCreateWindow(frame.header.reader_id);
        if (isReplay(window, frame.header.seq)) {
            return makeError("replay", frame.header);
        }
    }

    return processDecryption(frame, window);
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

HandleResult FrameHandler::processDecryption(const protocol::frame::Frame& frame,
                                             protocol::replay::ReplayWindow* window) {
    const auto decryptResult = _decryptor.decrypt(frame);

    if (!decryptResult.success) {
        return makeError(decryptResult.error, frame.header);
    }

    if (_config.antiReplayEnabled && window) {
        window->remember(frame.header.seq);
    }

    return HandleResult{.allow = true,
                        .reason = "ok",
                        .plaintext = decryptResult.plaintext,
                        .header = frame.header};
}

} // namespace access_core
