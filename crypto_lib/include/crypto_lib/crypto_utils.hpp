#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace crypto_lib::utils {
void hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data,
                 unsigned char out[32]);  // crypto_auth_hmacsha256_BYTES = 32


void le64(uint64_t x, unsigned char out[8]);

}  // namespace crypto_lib::utils