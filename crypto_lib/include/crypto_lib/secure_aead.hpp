#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

#include <sodium.h>

//! Authenticated encryption using XChaCha20-Poly1305.
namespace crypto_lib::aead {

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

//! XChaCha20-Poly1305 AEAD cipher with automatic nonce management.
class SecureAead {
  public:
    //! Encrypted data with tag and nonce for decryption.
    struct Ciphertext {
        //! Encrypted bytes (same length as plaintext).
        std::vector<uint8_t> ct;
        //! Authentication tag.
        Tag tag;
        //! 24-byte nonce used for encryption.
        std::array<uint8_t, 24> nonce;
    };

    //! Constructs an AEAD instance with the given key.
    //! Generates a random 16-byte nonce prefix.
    //! @param [in] key 256-bit encryption key.
    explicit SecureAead(const AeadKey& key);

    //! Encrypts plaintext with automatic sequence number management.
    //! Increments internal sequence counter after each call.
    //! @param [in] plaintext Data to encrypt.
    //! @param [in] aad       Additional authenticated data (not encrypted).
    //! @return Ciphertext with tag and nonce.
    //! @throws std::runtime_error If sequence counter overflows.
    Ciphertext seal(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad);

    //! Encrypts plaintext with an explicit sequence number.
    //! Does not modify internal sequence counter.
    //! @param [in] plaintext Data to encrypt.
    //! @param [in] aad       Additional authenticated data.
    //! @param [in] seq       Sequence number for nonce derivation.
    //! @return Ciphertext with tag and nonce.
    Ciphertext sealWithSeq(std::span<const uint8_t> plaintext,
                           std::span<const uint8_t> aad,
                           uint64_t seq);

    //! Decrypts ciphertext using the provided nonce.
    //! @param [in] ct    Ciphertext bytes.
    //! @param [in] tag   Authentication tag.
    //! @param [in] aad   Additional authenticated data (must match encryption).
    //! @param [in] nonce 24-byte nonce used during encryption.
    //! @return Decrypted plaintext.
    //! @throws std::runtime_error If authentication fails.
    std::vector<uint8_t> openWithNonce(std::span<const uint8_t> ct,
                                       const Tag& tag,
                                       std::span<const uint8_t> aad,
                                       const std::array<uint8_t, 24>& nonce);

    //! Derives a 24-byte nonce from prefix and sequence number.
    //! @param [in] seq Sequence number (8 bytes, little-endian).
    //! @return 24-byte nonce (prefix || seq).
    std::array<uint8_t, 24> deriveNonce(uint64_t seq) const;

  private:
    //! Encryption key.
    AeadKey _key;
    //! Random 16-byte prefix for nonce generation.
    std::array<uint8_t, 16> _noncePrefix{};
    //! Internal sequence counter for seal().
    uint64_t _seq = 0;

    //! Performs XChaCha20-Poly1305 encryption (detached mode).
    //! @param [in]  plaintext Data to encrypt.
    //! @param [in]  aad       Additional authenticated data.
    //! @param [in]  nonce     24-byte nonce.
    //! @param [out] out       Output ciphertext and tag.
    void encryptDetached(const std::span<const uint8_t>& plaintext,
                         const std::span<const uint8_t>& aad,
                         const std::array<uint8_t, 24>& nonce,
                         Ciphertext& out);

    //! Performs XChaCha20-Poly1305 decryption (detached mode).
    //! @param [in]  ct    Ciphertext bytes.
    //! @param [in]  tag   Authentication tag.
    //! @param [in]  aad   Additional authenticated data.
    //! @param [in]  nonce 24-byte nonce.
    //! @param [out] out   Output plaintext buffer.
    void decryptDetached(const std::span<const uint8_t>& ct,
                         const Tag& tag,
                         const std::span<const uint8_t>& aad,
                         const std::array<uint8_t, 24>& nonce,
                         std::vector<uint8_t>& out);
};

}  // namespace crypto_lib::aead
