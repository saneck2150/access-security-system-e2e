#include "crypto_lib/crypto_utils.hpp"

#include <stdexcept>

#include <sodium.h>

namespace crypto_lib::utils {

void hmac_sha256(std::span<const uint8_t> key,
                 std::span<const uint8_t> data,
                 unsigned char out[32]) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(&st, data.data(), data.size());
    crypto_auth_hmacsha256_final(&st, out);
}

void le64(uint64_t x, unsigned char out[8]) {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<unsigned char>((x >> (8 * i)) & 0xff);
    }
}

}  // namespace crypto_lib::utils
