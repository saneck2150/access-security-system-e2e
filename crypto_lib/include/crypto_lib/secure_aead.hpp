#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

#include <sodium.h>

//! Authenticated encryption using XChaCha20-Poly1305 or ChaCha20-Poly1305.
namespace crypto_lib::aead {

//! AEAD cipher variant to use.
enum class CipherMode {
    XChaCha20Poly1305,  //!< 192-bit nonce (24 bytes). Algorithm A2.
    ChaCha20Poly1305,   //!< 96-bit nonce (12 bytes, IETF RFC 8439). Algorithm A1.
};

//! 256-bit AEAD encryption key.
struct AeadKey {
    //! Raw key bytes (32 bytes = 256 bits).
    std::array<uint8_t, 32> key{};
};

//! 128-bit Poly1305 authentication tag.
struct Tag {
    //! Tag bytes (16 bytes = 128 bits).
    std::array<uint8_t, 16> v{};
};

//! AEAD cipher with automatic nonce management.
//! Supports XChaCha20-Poly1305 (24-byte nonce) and ChaCha20-Poly1305 (12-byte nonce).
//! The nonce field in Ciphertext is always 24 bytes; for ChaCha20 only the first 12 are used.
class SecureAead {
  public:
    //! Encrypted data with tag and nonce for decryption.
    struct Ciphertext {
        //! Encrypted bytes (same length as plaintext).
        std::vector<uint8_t> ct;
        //! Authentication tag.
        Tag tag;
        //! 24-byte nonce field. For ChaCha20Poly1305 only the first 12 bytes are meaningful.
        std::array<uint8_t, 24> nonce;
    };

    //! Constructs an AEAD instance with the given key and cipher mode.
    //! Generates a random nonce prefix.
    //! @param [in] key  256-bit encryption key.
    //! @param [in] mode Cipher variant (default: XChaCha20Poly1305).
    explicit SecureAead(const AeadKey& key, CipherMode mode = CipherMode::XChaCha20Poly1305);

    //! Encrypts plaintext with an explicit sequence number.
    //! Does not modify internal sequence counter.
    //! @param [in] plaintext Data to encrypt.
    //! @param [in] aad       Additional authenticated data.
    //! @param [in] seq       Sequence number for nonce derivation.
    //! @return Ciphertext with tag and nonce.
    Ciphertext sealWithSeq(
        std::span<const uint8_t> plaintext, std::span<const uint8_t> aad, uint64_t seq);

    //! Encrypts plaintext with an explicitly provided nonce.
    //! Use this when nonce is generated externally (e.g., by INonceGenerator).
    //! @param [in] plaintext Data to encrypt.
    //! @param [in] aad       Additional authenticated data.
    //! @param [in] nonce     24-byte nonce (for ChaCha20 only first 12 bytes are used).
    //! @return Ciphertext with tag and the provided nonce.
    Ciphertext sealWithNonce(std::span<const uint8_t> plaintext,
        std::span<const uint8_t> aad,
        const std::array<uint8_t, 24>& nonce);

    //! Decrypts ciphertext using the provided nonce.
    //! @param [in] ct    Ciphertext bytes.
    //! @param [in] tag   Authentication tag.
    //! @param [in] aad   Additional authenticated data (must match encryption).
    //! @param [in] nonce 24-byte nonce field (for ChaCha20 only first 12 bytes are used).
    //! @return Decrypted plaintext.
    //! @throws std::runtime_error If authentication fails.
    std::vector<uint8_t> openWithNonce(std::span<const uint8_t> ct,
        const Tag& tag,
        std::span<const uint8_t> aad,
        const std::array<uint8_t, 24>& nonce);

    //! Derives a nonce from prefix and sequence number.
    //! For XChaCha20: 16-byte prefix || 8-byte seq_le = 24 bytes.
    //! For ChaCha20:  4-byte prefix  || 8-byte seq_le = 12 bytes, stored in first 12 of 24.
    //! @param [in] seq Sequence number (8 bytes, little-endian).
    //! @return 24-byte array (first 12 or all 24 bytes meaningful depending on mode).
    std::array<uint8_t, 24> deriveNonce(uint64_t seq) const;

  private:
    //! Encryption key.
    AeadKey _key;
    //! Cipher variant.
    CipherMode _cipherMode;
    //! Random 16-byte prefix for nonce generation (ChaCha20 uses only first 4 bytes).
    std::array<uint8_t, 16> _noncePrefix{};

    //! Performs AEAD encryption (detached mode), dispatches on _cipherMode.
    void encryptDetached(const std::span<const uint8_t>& plaintext,
        const std::span<const uint8_t>& aad,
        const std::array<uint8_t, 24>& nonce,
        Ciphertext& out);

    //! Performs AEAD decryption (detached mode), dispatches on _cipherMode.
    void decryptDetached(const std::span<const uint8_t>& ct,
        const Tag& tag,
        const std::span<const uint8_t>& aad,
        const std::array<uint8_t, 24>& nonce,
        std::vector<uint8_t>& out);
};

}  // namespace crypto_lib::aead
