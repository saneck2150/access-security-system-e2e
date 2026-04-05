#include "access_core/handle_frame.hpp"

#include <stdexcept>
#include <string_view>
#include <variant>

#include <access_decision/access_store.hpp>
#include <crypto_lib/secure_aead.hpp>

namespace access_core {

namespace {

//! Maps protocol_lib exception messages to error codes.
//! @param [in] what Exception message from std::runtime_error.
//! @return Specific error code or "parse_error" as fallback.
std::string parseErrorToCode(std::string_view what) {
    if (what.find("too small") != std::string_view::npos) {
        return "frame_too_small";
    }
    if (what.find("bad magic") != std::string_view::npos) {
        return "bad_magic";
    }
    if (what.find("bad version") != std::string_view::npos) {
        return "bad_protocol_version";
    }
    if (what.find("ctLen exceeds") != std::string_view::npos) {
        return "ciphertext_too_large";
    }
    if (what.find("length mismatch") != std::string_view::npos) {
        return "frame_truncated";
    }
    if (what.find("trailing bytes") != std::string_view::npos) {
        return "frame_trailing_bytes";
    }
    return "parse_error";
}

}  // namespace

FrameHandler::FrameHandler(const key_manager::KeyManager& keyManager,
    ReplayWindowMap& replayWindows,
    const access_decision::IAccessStore* store,
    FrameHandlerConfig config)
    : _keyManager(keyManager), _replayWindows(replayWindows), _store(store), _config(config) {}

std::variant<protocol::frame::Frame, HandleResult> FrameHandler::parseFrame(
    std::span<const uint8_t> frameBytes) {
    try {
        return protocol::frame::parseFrame(frameBytes, _config.maxCtLen);
    } catch (const std::runtime_error& e) {
        return makeError(parseErrorToCode(e.what()));
    } catch (...) {
        return makeError("parse_error");
    }
}

std::optional<HandleResult> FrameHandler::validateReader(
    const protocol::frame::Frame& frame, uint32_t& outKeyVersion) {
    if (!_store) {
        return makeError("no_store", frame.header);
    }

    outKeyVersion = _store->currentKeyVersionForReader(frame.header.reader_id);
    if (outKeyVersion == 0) {
        return makeError("unknown_reader", frame.header);
    }

    if (_config.enforceReaderDoorBinding) {
        if (!_store->isReaderAllowedDoor(frame.header.reader_id, frame.header.door_id)) {
            return makeError("reader_door_forbidden", frame.header);
        }
    }
    return std::nullopt;
}

std::optional<HandleResult> FrameHandler::validateKeyVersion(
    const protocol::frame::Frame& frame, uint32_t currentKv) {
    const uint32_t kv = frame.header.key_version;
    const bool acceptPrev = _config.allowPreviousKeyVersion;
    const bool keyOk = (kv == currentKv) || (acceptPrev && currentKv > 1 && kv + 1 == currentKv);
    if (!keyOk) {
        return makeError("bad_key_version", frame.header);
    }
    return std::nullopt;
}

std::optional<HandleResult> FrameHandler::checkReplay(
    const protocol::frame::Frame& frame, protocol::replay::ReplayWindow*& outWindow) {
    outWindow = nullptr;
    if (!_config.antiReplayEnabled) {
        return std::nullopt;
    }
    outWindow = getOrCreateWindow(frame.header.reader_id);
    if (isReplay(outWindow, frame.header.seq)) {
        return makeError("replay", frame.header);
    }
    return std::nullopt;
}

HandleResult FrameHandler::handle(std::span<const uint8_t> frameBytes) {
    auto parseResult = parseFrame(frameBytes);
    if (std::holds_alternative<HandleResult>(parseResult)) {
        return std::get<HandleResult>(parseResult);
    }
    const auto& frame = std::get<protocol::frame::Frame>(parseResult);

    uint32_t currentKeyVersion = 0;
    if (auto err = validateReader(frame, currentKeyVersion)) {
        return *err;
    }
    if (auto err = validateKeyVersion(frame, currentKeyVersion)) {
        return *err;
    }

    protocol::replay::ReplayWindow* window = nullptr;
    if (auto err = checkReplay(frame, window)) {
        return *err;
    }

    return tryDecrypt(frame, window);
}

HandleResult FrameHandler::makeError(
    const std::string& reason, const protocol::packet::Header& header) const {
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

std::variant<crypto_lib::aead::AeadKey, HandleResult> FrameHandler::deriveKey(
    const protocol::frame::Frame& frame) {
    try {
        if (_config.keyDerivationMode == "direct") {
            return _keyManager.masterAsAeadKey();
        }
        return _keyManager.deriveAeadKey(frame.header.reader_id, frame.header.key_version);
    } catch (...) {
        return makeError("key_derivation_failed", frame.header);
    }
}

std::string FrameHandler::decryptExceptionToCode(const std::exception& e) const {
    std::string_view what = e.what();
    if (what.find("mac") != std::string_view::npos || what.find("tag") != std::string_view::npos ||
        what.find("auth") != std::string_view::npos) {
        return "mac_verification_failed";
    }
    return "decrypt_failed";
}

HandleResult FrameHandler::tryDecrypt(
    const protocol::frame::Frame& frame, protocol::replay::ReplayWindow* window) {
    auto keyResult = deriveKey(frame);
    if (std::holds_alternative<HandleResult>(keyResult)) {
        return std::get<HandleResult>(keyResult);
    }
    const auto& aeadKey = std::get<crypto_lib::aead::AeadKey>(keyResult);

    try {
        const auto cipherMode = (_config.cipherMode == "chacha20")
                                    ? crypto_lib::aead::CipherMode::ChaCha20Poly1305
                                    : crypto_lib::aead::CipherMode::XChaCha20Poly1305;
        crypto_lib::aead::SecureAead aead(aeadKey, cipherMode);
        FrameDecryptor decryptor(
            aead, DecryptorConfig{.maxSkewMs = _config.maxSkewMs, .aadMode = _config.aadMode});

        auto dec = decryptor.decrypt(frame);
        if (!dec.success) {
            return makeError(dec.error, frame.header);
        }

        if (_config.antiReplayEnabled && window) {
            window->remember(frame.header.seq);
        }

        return HandleResult{.allow = true,
            .reason = "ok",
            .plaintext = std::move(dec.plaintext),
            .header = frame.header};
    } catch (const std::exception& e) {
        return makeError(decryptExceptionToCode(e), frame.header);
    } catch (...) {
        return makeError("decrypt_failed", frame.header);
    }
}

}  // namespace access_core
