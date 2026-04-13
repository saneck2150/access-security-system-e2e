#pragma once

//! @file frame_factory.hpp
//! Builds encrypted frames and provides byte-level tampering helpers.

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <crypto_lib/nonce_generator.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <key_manager/key_manager.hpp>

namespace experiments {

//! Configuration for a single experiment profile.
struct ProfileConfig {
    std::string label;                              //!< e.g. "A1-R0"
    std::string cipherMode = "xchacha20";           //!< "chacha20" or "xchacha20"
    std::string nonceMode = "deterministic";        //!< "random" or "deterministic"
    std::string keyDerivationMode = "hkdf";
    std::string aadMode = "full";
    std::string pepperMode = "versioned";
    bool detectorEnabled = false;
    uint64_t rollbackThreshold = 100;
    uint32_t tagFailStreakLimit = 5;
};

//! Builds encrypted frame bytes for experiment scenarios.
//! Mirrors hw_service.cpp logic using lower-level primitives.
class FrameFactory {
  public:
    //! @param [in] km       KeyManager for key derivation.
    //! @param [in] profile  Profile configuration.
    //! @param [in] nonceGen Nonce generator (Seeded for R0, HMAC for R1/R2).
    FrameFactory(const key_manager::KeyManager& km,
        const ProfileConfig& profile,
        std::unique_ptr<crypto_lib::nonce::INonceGenerator> nonceGen);

    //! Builds a valid encrypted frame.
    std::vector<uint8_t> buildFrame(uint32_t readerId, uint32_t doorId,
        uint64_t seq, uint32_t keyVersion, uint64_t tsUnixMs,
        std::string_view cardId, std::string_view action = "open");

    // --- Byte-level tampering (static, work on serialized bytes) ---

    //! Modifies door_id at bytes [9..12].
    static std::vector<uint8_t> tamperDoorId(
        const std::vector<uint8_t>& frameBytes, uint32_t newDoorId);

    //! Modifies reader_id at bytes [5..8].
    static std::vector<uint8_t> tamperReaderId(
        const std::vector<uint8_t>& frameBytes, uint32_t newReaderId);

    //! Replaces ciphertext with deterministic garbage (XOR with 0xFF).
    static std::vector<uint8_t> tamperCiphertext(
        const std::vector<uint8_t>& frameBytes);

    //! XOR nonce bytes with 0xFF — simulates MITM nonce tampering in transit.
    static std::vector<uint8_t> tamperNonce(const std::vector<uint8_t>& frameBytes);

    //! Modifies seq at bytes [21..28].
    static std::vector<uint8_t> tamperSeq(
        const std::vector<uint8_t>& frameBytes, uint64_t newSeq);

  private:
    const key_manager::KeyManager& _km;
    ProfileConfig _profile;
    std::unique_ptr<crypto_lib::nonce::INonceGenerator> _nonceGen;

    crypto_lib::aead::CipherMode cipherModeEnum() const;
};

}  // namespace experiments
