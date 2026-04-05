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

//! Frame handling: parsing, replay detection, key rotation, and AEAD decryption.
namespace access_core {

//! Configuration for FrameHandler behavior.
struct FrameHandlerConfig {
    //! Enable replay attack detection.
    bool antiReplayEnabled = true;
    //! Size of sliding replay window.
    size_t replayWindowSize = 256;
    //! Maximum ciphertext length.
    uint32_t maxCtLen = 4096;
    //! Max timestamp skew (0 = disabled).
    uint64_t maxSkewMs = 0;
    //! Accept previous key version.
    bool allowPreviousKeyVersion = true;
    //! Verify reader-door authorization.
    bool enforceReaderDoorBinding = true;

    //! Key derivation mode: "hkdf" (per-reader HKDF) or "direct" (master key as AEAD key).
    //! Populated at runtime from ExperimentConfig, not loaded directly from YAML.
    std::string keyDerivationMode = "hkdf";
    //! AAD binding mode: "full" (header bytes as AAD) or "none" (empty AAD).
    //! Populated at runtime from ExperimentConfig, not loaded directly from YAML.
    std::string aadMode = "full";
    //! Pepper mode: "versioned" (HKDF per key version) or "static" (fixed version 1).
    //! Populated at runtime from ExperimentConfig, not loaded directly from YAML.
    std::string pepperMode = "versioned";
    //! AEAD cipher: "xchacha20" (XChaCha20-Poly1305) or "chacha20" (ChaCha20-Poly1305 IETF).
    //! Populated at runtime from ExperimentConfig, not loaded directly from YAML.
    std::string cipherMode = "xchacha20";
    //! Nonce strategy: "deterministic" (HMAC-based, R1/R2) or "random" (randombytes, R0).
    //! Populated at runtime from ExperimentConfig.
    std::string nonceMode = "deterministic";
};

//! Result of frame handling operation.
struct HandleResult {
    //! True if frame is valid.
    bool allow = false;
    //! Result code (e.g., "ok", "replay").
    std::string reason;
    //! Decrypted payload (if successful).
    std::vector<uint8_t> plaintext;
    //! Parsed frame header.
    protocol::packet::Header header;
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
    HandleResult makeError(
        const std::string& reason, const protocol::packet::Header& header = {}) const;

    //! Parses frame bytes into Frame structure.
    std::variant<protocol::frame::Frame, HandleResult> parseFrame(
        std::span<const uint8_t> frameBytes);

    //! Validates reader registration and door binding.
    std::optional<HandleResult> validateReader(
        const protocol::frame::Frame& frame, uint32_t& outKeyVersion);

    //! Validates frame key version against current/previous.
    std::optional<HandleResult> validateKeyVersion(
        const protocol::frame::Frame& frame, uint32_t currentKv);

    //! Checks for replay attacks using sliding window.
    std::optional<HandleResult> checkReplay(
        const protocol::frame::Frame& frame, protocol::replay::ReplayWindow*& outWindow);

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
    HandleResult tryDecrypt(
        const protocol::frame::Frame& frame, protocol::replay::ReplayWindow* window);
};
}  // namespace access_core
