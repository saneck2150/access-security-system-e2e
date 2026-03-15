#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>

#include <sodium.h>

#include <crypto_lib/secure_aead.hpp>

//! Nonce generation strategies for AEAD.
//! Separates nonce derivation from encryption (SRP).
namespace crypto_lib::nonce {

//! Returns the effective nonce length for a given cipher mode.
//! @param [in] mode Cipher variant.
//! @return 12 for ChaCha20-Poly1305, 24 for XChaCha20-Poly1305.
constexpr size_t nonceLenFor(aead::CipherMode mode) {
    return (mode == aead::CipherMode::XChaCha20Poly1305) ? 24 : 12;
}

//! Interface for nonce generation strategies.
//! Each implementation represents a deployment mode (R0, R1/R2).
class INonceGenerator {
  public:
    virtual ~INonceGenerator() = default;

    //! Generates a nonce for a frame.
    //! @param [in] context Serialized header fields (without nonce) used as HMAC input
    //!                     in deterministic mode; ignored in random mode.
    //! @param [in] seq     Sequence number of the frame.
    //! @return 24-byte nonce array. For ChaCha20 only the first 12 bytes are meaningful.
    virtual std::array<uint8_t, 24> generate(
        std::span<const uint8_t> context, uint64_t seq) = 0;
};

//! R0 — Random nonce generation.
//! Generates nonce via randombytes_buf(). RNG-dependent.
//! Context is ignored; each call produces a fresh random nonce.
class RandomNonceGenerator final : public INonceGenerator {
  public:
    //! @param [in] cipherMode Determines nonce length (12 or 24 bytes).
    explicit RandomNonceGenerator(aead::CipherMode cipherMode);

    std::array<uint8_t, 24> generate(
        std::span<const uint8_t> context, uint64_t seq) override;

  private:
    size_t _nonceLen;
};

//! R1/R2 — Deterministic HMAC-based nonce.
//! nonce = HMAC-SHA-256(K_nonce, context)[:nonce_len].
//! RNG-independent; nonce is bound to full message context.
class HmacNonceGenerator final : public INonceGenerator {
  public:
    //! @param [in] nonceKey   32-byte key derived via HKDF (info="nonce-derivation-v1").
    //! @param [in] cipherMode Determines nonce length (12 or 24 bytes).
    HmacNonceGenerator(const aead::AeadKey& nonceKey, aead::CipherMode cipherMode);

    std::array<uint8_t, 24> generate(
        std::span<const uint8_t> context, uint64_t seq) override;

  private:
    aead::AeadKey _nonceKey;
    size_t _nonceLen;
};

}  // namespace crypto_lib::nonce
