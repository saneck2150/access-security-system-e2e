#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <sodium.h>

//! HKDF (HMAC-based Key Derivation Function) implementation per RFC 5869.
namespace crypto_lib::hkdf {

//! Derives cryptographic keys from input keying material using HKDF-SHA256.
class Hkdf {
  public:
    //! Constructs an HKDF instance and performs the extract phase.
    //! @param [in] ikm       Input keying material (master key).
    //! @param [in] salt      Optional salt (random, non-secret).
    //! @param [in] info      Context/application-specific info string.
    //! @param [in] outputLen Desired output key length in bytes.
    Hkdf(std::span<const uint8_t> ikm,
         std::span<const uint8_t> salt,
         std::string_view info,
         size_t outputLen);

    //! Performs the expand phase and returns the derived key.
    //! @return Derived key material of the requested length.
    std::vector<uint8_t> derive();

  private:
    //! HMAC-SHA256 output size (32 bytes).
    const size_t _hashLen = crypto_auth_hmacsha256_BYTES;

    //! Input keying material.
    std::span<const uint8_t> _ikm;
    //! Optional salt for extract phase.
    std::span<const uint8_t> _salt;
    //! Context info string for expand phase.
    std::string_view _info;
    //! Requested output length.
    size_t _outputLen;

    //! Pseudorandom key from extract phase.
    std::array<uint8_t, crypto_auth_hmacsha256_BYTES> _prk;
    //! Output keying material (accumulated during expand).
    std::vector<uint8_t> _okm;
    //! Previous block for chaining in expand phase.
    std::vector<unsigned char> _prevBlock;

    //! Performs HKDF-Extract: PRK = HMAC(salt, IKM).
    void extract();

    //! Calculates number of blocks needed for output length.
    //! @return Number of HMAC blocks to generate.
    size_t computeBlockCount() const;

    //! Expands one block of output keying material.
    //! @param [in] blockIndex 1-based block index (also used as counter byte).
    void expandBlock(size_t blockIndex);

    //! Initializes HMAC state with PRK as key.
    //! @param [out] state HMAC state to initialize.
    void initHmacState(crypto_auth_hmacsha256_state& state) const;

    //! Updates HMAC state with the previous block (for chaining).
    //! @param [in,out] state HMAC state to update.
    void updateWithPrevBlock(crypto_auth_hmacsha256_state& state) const;

    //! Updates HMAC state with the info string.
    //! @param [in,out] state HMAC state to update.
    void updateWithInfo(crypto_auth_hmacsha256_state& state) const;

    //! Updates HMAC state with the 1-byte block index counter.
    //! @param [in,out] state      HMAC state to update.
    //! @param [in]     blockIndex Block index (1-255).
    void updateWithBlockIndex(crypto_auth_hmacsha256_state& state, size_t blockIndex) const;

    //! Finalizes HMAC and appends result to output keying material.
    //! @param [in,out] state HMAC state to finalize.
    void finalizeAndAppend(crypto_auth_hmacsha256_state& state);
};

}  // namespace crypto_lib::hkdf
