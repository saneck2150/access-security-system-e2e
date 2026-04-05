#pragma once

//! @file seeded_nonce_generator.hpp
//! Deterministic nonce generator for reproducible R0 experiments.

#include <array>
#include <cstdint>
#include <span>

#include <crypto_lib/nonce_generator.hpp>
#include <crypto_lib/secure_aead.hpp>

namespace experiments {

//! Deterministic replacement for RandomNonceGenerator (R0 mode).
//! Uses crypto_stream_chacha20_ietf with a fixed seed to produce
//! reproducible nonces. Nonce = f(seed, seq) — pure function, no state.
class SeededNonceGenerator final : public crypto_lib::nonce::INonceGenerator {
  public:
    //! @param [in] seed       32-byte seed used as ChaCha20 key.
    //! @param [in] cipherMode Determines nonce length (12 or 24).
    SeededNonceGenerator(const std::array<uint8_t, 32>& seed,
        crypto_lib::aead::CipherMode cipherMode);

    //! Generates a deterministic nonce from (seed, seq).
    //! @param [in] context Ignored (R0 does not bind nonce to context).
    //! @param [in] seq     Used as ChaCha20 block counter for determinism.
    //! @return 24-byte array; first nonce_len bytes are meaningful.
    std::array<uint8_t, 24> generate(
        std::span<const uint8_t> context, uint64_t seq) override;

  private:
    std::array<uint8_t, 32> _seed;
    size_t _nonceLen;
};

}  // namespace experiments
