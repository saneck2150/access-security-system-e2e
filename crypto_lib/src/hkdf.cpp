#include "crypto_lib/hkdf.hpp"
#include "crypto_lib/crypto_utils.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

namespace crypto_lib::hkdf {

using crypto_lib::utils::hmac_sha256;

std::array<unsigned char, crypto_auth_hmacsha256_BYTES> hkdf_extract(std::span<const uint8_t> salt,
                                                                     std::span<const uint8_t> ikm) {
    std::array<unsigned char, crypto_auth_hmacsha256_BYTES> prk{};
    if (salt.empty()) {
        std::array<unsigned char, crypto_auth_hmacsha256_BYTES> zeros{};
        hmac_sha256(zeros, ikm, prk.data());
    } else {
        hmac_sha256(salt, ikm, prk.data());
    }
    return prk;
}

std::vector<uint8_t> hkdf_expand(std::span<const uint8_t> prk, std::string_view info, size_t L) {
    const size_t hash_len = crypto_auth_hmacsha256_BYTES;
    const size_t n = (L + hash_len - 1) / hash_len;
    if (n > 255)
        throw std::invalid_argument("hkdf_expand: L too large");

    std::vector<uint8_t> okm;
    okm.reserve(L);

    std::vector<unsigned char> T;
    T.reserve(hash_len);

    for (size_t i = 1; i <= n; ++i) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
        if (!T.empty())
            crypto_auth_hmacsha256_update(&st, T.data(), T.size());
        if (!info.empty())
            crypto_auth_hmacsha256_update(&st, reinterpret_cast<const unsigned char*>(info.data()),
                                          info.size());
        const unsigned char c = static_cast<unsigned char>(i);
        crypto_auth_hmacsha256_update(&st, &c, 1);

        T.resize(hash_len);
        crypto_auth_hmacsha256_final(&st, T.data());

        const size_t to_copy = std::min(hash_len, L - okm.size());
        okm.insert(okm.end(), T.begin(), T.begin() + to_copy);
    }
    return okm;
}

std::vector<uint8_t> hkdf_sha256(std::span<const uint8_t> ikm, std::span<const uint8_t> salt,
                                 std::string_view info, size_t out_len) {
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");
    auto prk = hkdf_extract(salt, ikm);
    return hkdf_expand(std::span<const uint8_t>(prk.data(), prk.size()), info, out_len);
}

}  // namespace crypto_lib::hkdf
