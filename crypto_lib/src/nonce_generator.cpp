#include "crypto_lib/nonce_generator.hpp"

#include <cstring>

namespace crypto_lib::nonce {

// --- RandomNonceGenerator (R0) ---

RandomNonceGenerator::RandomNonceGenerator(aead::CipherMode cipherMode)
    : _nonceLen(nonceLenFor(cipherMode)) {}

std::array<uint8_t, 24> RandomNonceGenerator::generate(
    std::span<const uint8_t> /*context*/, uint64_t /*seq*/) {
    std::array<uint8_t, 24> nonce{};
    randombytes_buf(nonce.data(), _nonceLen);
    return nonce;
}

// --- HmacNonceGenerator (R1/R2) ---

HmacNonceGenerator::HmacNonceGenerator(const aead::AeadKey& nonceKey, aead::CipherMode cipherMode)
    : _nonceKey(nonceKey), _nonceLen(nonceLenFor(cipherMode)) {}

std::array<uint8_t, 24> HmacNonceGenerator::generate(
    std::span<const uint8_t> context, uint64_t /*seq*/) {
    // HMAC-SHA-256(K_nonce, context) → 32 bytes, truncate to nonce_len
    unsigned char mac[crypto_auth_hmacsha256_BYTES];  // 32 bytes
    crypto_auth_hmacsha256(mac,
        context.data(),
        context.size(),
        reinterpret_cast<const unsigned char*>(_nonceKey.key.data()));

    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), mac, _nonceLen);

    // Zero the full HMAC output on stack
    sodium_memzero(mac, sizeof(mac));

    return nonce;
}

}  // namespace crypto_lib::nonce
