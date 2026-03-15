#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

//! Low-level cryptographic utility functions.
namespace crypto_lib::utils {

//! Computes HMAC-SHA256 over data using the given key.
//! @param [in] key  HMAC key bytes.
//! @param [in] data Input data to authenticate.
//! @param [out] out Output buffer (must be 32 bytes).
void hmac_sha256(std::span<const uint8_t> key,
    std::span<const uint8_t> data,
    unsigned char out[32]);  // crypto_auth_hmacsha256_BYTES = 32

//! Encodes a 64-bit unsigned integer in little-endian format.
//! @param [in] x   Value to encode.
//! @param [out] out Output buffer (must be 8 bytes).
void le64(uint64_t x, unsigned char out[8]);

}  // namespace crypto_lib::utils
