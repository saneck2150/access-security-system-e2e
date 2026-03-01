#pragma once

//! @file handle_frame.hpp
//! Frame handling with decryption, replay detection, and key rotation.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include <key_manager/key_manager.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>
#include <protocol_lib/replay_window.hpp>

#include "access_core/frame_decryptor.hpp"

namespace access_decision {
class IAccessStore;
}

namespace access_core {

//! Configuration for FrameHandler behavior.
struct FrameHandlerConfig {
    bool antiReplayEnabled = true;         //!< Enable replay attack detection.
    size_t replayWindowSize = 256;         //!< Size of sliding replay window.
    uint32_t maxCtLen = 4096;              //!< Maximum ciphertext length.
    uint64_t maxSkewMs = 0;                //!< Max timestamp skew (0 = disabled).
    bool allowPreviousKeyVersion = true;   //!< Accept previous key version.
    bool enforceReaderDoorBinding = true;  //!< Verify reader-door authorization.
};

//! Result of frame handling operation.
struct HandleResult {
    bool allow = false;               //!< True if frame is valid.
    std::string reason;               //!< Result code (e.g., "ok", "replay").
    std::vector<uint8_t> plaintext;   //!< Decrypted payload (if successful).
    protocol::packet::Header header;  //!< Parsed frame header.
};

//! Handles encrypted frames from readers with full validation.
//! Performs parsing, replay detection, key version checks, and decryption.
class FrameHandler {
  public:
    using ReplayWindowMap = std::unordered_map<uint32_t, protocol::replay::ReplayWindow>;

    //! Constructs a FrameHandler.
    //! @param [in]     keyManager    Key manager for AEAD key derivation.
    //! @param [in,out] replayWindows Per-reader replay windows (modified on
    //! success).
    //! @param [in]     store         Access store for reader/door validation.
    //! @param [in]     config        Handler configuration.
    FrameHandler(const key_manager::KeyManager& keyManager,
                 ReplayWindowMap& replayWindows,
                 const access_decision::IAccessStore* store,
                 FrameHandlerConfig config = {});

    //! Processes a frame and returns validation result with decrypted payload.
    //! @param [in] frameBytes Raw frame bytes from reader.
    //! @return HandleResult with allow/reason and plaintext if successful.
    HandleResult handle(std::span<const uint8_t> frameBytes);

  private:
    const key_manager::KeyManager& _keyManager;
    ReplayWindowMap& _replayWindows;
    const access_decision::IAccessStore* _store = nullptr;
    FrameHandlerConfig _config;

    //! Creates an error result with given reason.
    HandleResult makeError(const std::string& reason,
                           const protocol::packet::Header& header = {}) const;

    //! Parses frame bytes into Frame structure.
    std::variant<protocol::frame::Frame, HandleResult> parseFrame(
        std::span<const uint8_t> frameBytes);

    //! Validates reader registration and door binding.
    std::optional<HandleResult> validateReader(const protocol::frame::Frame& frame,
                                               uint32_t& outKeyVersion);

    //! Validates frame key version against current/previous.
    std::optional<HandleResult> validateKeyVersion(const protocol::frame::Frame& frame,
                                                   uint32_t currentKv);

    //! Checks for replay attacks using sliding window.
    std::optional<HandleResult> checkReplay(const protocol::frame::Frame& frame,
                                            protocol::replay::ReplayWindow*& outWindow);

    //! Gets or creates replay window for a reader.
    protocol::replay::ReplayWindow* getOrCreateWindow(uint32_t readerId);

    //! Checks if sequence number was already seen.
    bool isReplay(protocol::replay::ReplayWindow* window, uint64_t seq) const;

    //! Derives AEAD key for the frame.
    std::variant<crypto_lib::aead::AeadKey, HandleResult> deriveKey(
        const protocol::frame::Frame& frame);

    //! Maps decryption exception to error code.
    std::string decryptExceptionToCode(const std::exception& e) const;

    //! Attempts decryption with derived AEAD key.
    HandleResult tryDecrypt(const protocol::frame::Frame& frame,
                            protocol::replay::ReplayWindow* window);
};
}  // namespace access_core
