#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <crypto_lib/hkdf.hpp>
#include <crypto_lib/secure_aead.hpp>

namespace key_manager {

//! Size of the master key in bytes (256-bit).
constexpr size_t kMasterKeySize = 32;

//! Size of derived AEAD keys in bytes (256-bit for XChaCha20-Poly1305).
constexpr size_t kAeadKeySize = 32;

//! Size of card pepper in bytes (256-bit).
constexpr size_t kCardPepperSize = 32;

//! Size of audit HMAC key in bytes (256-bit).
constexpr size_t kAuditHmacKeySize = 32;

//! Number of hex characters required for master key (64 hex = 32 bytes).
constexpr size_t kMasterKeyHexChars = kMasterKeySize * 2;

//! Configuration for KeyManager versioning and rollback policy.
struct KeyManagerConfig {
    //! Current active key version for encryption/signing.
    uint32_t currentKeyVersion = 1;
    //! If true, accept frames encrypted with (currentKeyVersion - 1).
    bool allowPreviousKeyVersion = true;
};

//! Derives cryptographic keys from a master secret using HKDF.
//! Supports key versioning for rotation and domain separation for different
//! uses.
class KeyManager {
  public:
    //! 256-bit master key type.
    using MasterKey = std::array<uint8_t, kMasterKeySize>;

    //! Constructs a KeyManager with the given master key and configuration.
    //! @param masterKey [in] 32-byte master secret for key derivation.
    //! @param cfg [in] Key versioning configuration.
    //! @throws std::invalid_argument if currentKeyVersion is 0.
    KeyManager(MasterKey masterKey, KeyManagerConfig cfg = {});

    //! Checks if a key version is acceptable for decryption.
    //! @param keyVersion [in] Version to check.
    //! @return True if version equals current or (current-1 if allowed).
    bool isAcceptedKeyVersion(uint32_t keyVersion) const;

    //! Derives an AEAD key for frame encryption/decryption.
    //! @param readerId [in] Reader ID for domain separation.
    //! @param keyVersion [in] Key version for rotation support.
    //! @return 32-byte AEAD key derived via HKDF.
    crypto_lib::aead::AeadKey deriveAeadKey(uint32_t readerId, uint32_t keyVersion) const;

    //! Derives a pepper for hashing card IDs.
    //! @param keyVersion [in] Key version for rotation support.
    //! @return 32-byte pepper derived via HKDF.
    //! @throws std::invalid_argument if keyVersion is 0.
    std::array<uint8_t, kCardPepperSize> deriveCardPepper(uint32_t keyVersion) const;

    //! Derives the HMAC key for audit log chain integrity.
    //! @return 32-byte HMAC key derived via HKDF.
    std::array<uint8_t, kAuditHmacKeySize> deriveAuditHmacKey() const;

    //! Returns the master key directly as an AEAD key (no derivation).
    //! Used when key_derivation_mode="direct" (all readers share the same key).
    //! @return Master key wrapped as AeadKey.
    crypto_lib::aead::AeadKey masterAsAeadKey() const;

    //! Derives a key for deterministic nonce generation (R1/R2).
    //! salt = reader_id(4B LE) || key_version(4B LE), info = "nonce-derivation-v1".
    //! @param [in] readerId   Reader ID for domain separation.
    //! @param [in] keyVersion Key version for rotation support.
    //! @return 32-byte nonce key derived via HKDF.
    crypto_lib::aead::AeadKey deriveNonceKey(uint32_t readerId, uint32_t keyVersion) const;

  private:
    //! Master secret used as input key material for HKDF.
    MasterKey _masterKey{};
    //! Key versioning configuration.
    KeyManagerConfig _cfg{};

    //! Writes a 32-bit value in little-endian format.
    //! @param v [in] Value to encode.
    //! @param out [out] 4-byte output buffer.
    void putLe32(uint32_t v, uint8_t out[4]) const;
};

//! Loads a master key from a hex-encoded file.
//! @param path [in] Path to file containing 64 hex characters.
//! @return Parsed 32-byte master key.
//! @throws std::runtime_error if file cannot be opened.
//! @throws std::invalid_argument if hex is invalid or wrong length.
KeyManager::MasterKey loadMasterKeyHexFile(const std::string& path);

}  // namespace key_manager
