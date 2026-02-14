#pragma once

#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto_lib::hkdf {

class Hkdf {
  public:
    Hkdf(std::span<const uint8_t> ikm, std::span<const uint8_t> salt, std::string_view info,
         size_t outputLen);

    std::vector<uint8_t> derive();

  private:
    const size_t _hashLen = crypto_auth_hmacsha256_BYTES;

    // input
    std::span<const uint8_t> _ikm;
    std::span<const uint8_t> _salt;
    std::string_view _info;
    size_t _outputLen;

    std::array<uint8_t, crypto_auth_hmacsha256_BYTES> _prk;
    std::vector<uint8_t> _okm;
    std::vector<unsigned char> _prevBlock;

    void extract();

    size_t computeBlockCount() const;
    void expandBlock(size_t blockIndex);
    void initHmacState(crypto_auth_hmacsha256_state& state) const;
    void updateWithPrevBlock(crypto_auth_hmacsha256_state& state) const;
    void updateWithInfo(crypto_auth_hmacsha256_state& state) const;
    void updateWithBlockIndex(crypto_auth_hmacsha256_state& state, size_t blockIndex) const;
    void finalizeAndAppend(crypto_auth_hmacsha256_state& state);
};

} // namespace crypto_lib::hkdf