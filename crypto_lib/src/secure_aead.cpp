#include "crypto_lib/secure_aead.hpp"
#include "crypto_lib/crypto_utils.hpp"

#include <sodium.h>

#include <cstring>
#include <limits>

namespace crypto_lib::aead {

using crypto_lib::utils::le64;

/// @todo Proper inicialization process
/// https://saneck2150-1760865460652.atlassian.net/browse/DIP-41?atlOrigin=eyJpIjoiN2Y3M2U0NTRlZTBhNDFhMTk2ZTY5NGQ1NzI5ZWM0NmYiLCJwIjoiaiJ9
bool SecureAead::_sodiumInitialized = true;

/// @todo Proper inicialization process
/// https://saneck2150-1760865460652.atlassian.net/browse/DIP-41?atlOrigin=eyJpIjoiN2Y3M2U0NTRlZTBhNDFhMTk2ZTY5NGQ1NzI5ZWM0NmYiLCJwIjoiaiJ9
void SecureAead::ensure_sodium() {
    if (!SecureAead::_sodiumInitialized) {
        if (sodium_init() < 0)
            throw std::runtime_error("libsodium init failed");
    }
}

SecureAead::SecureAead(AeadKey k) : _key(k) {
    ensure_sodium();
    randombytes_buf(_noncePrefix.data(), _noncePrefix.size());
}

std::array<uint8_t, 24> SecureAead::derive_nonce(uint64_t seq) const {
    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), _noncePrefix.data(), _noncePrefix.size());
    le64(seq, nonce.data() + _noncePrefix.size());
    return nonce;
}

SecureAead::Ciphertext SecureAead::seal_with_seq(std::span<const uint8_t> plaintext,
                                                 std::span<const uint8_t> aad, uint64_t seq) {
    ensure_sodium();
    auto nonce = derive_nonce(seq);

    SecureAead::Ciphertext out;
    out.ct.resize(plaintext.size());
    out.nonce = nonce;

    unsigned long long maclen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            out.ct.data(), out.tag.v.data(), &maclen, plaintext.data(), plaintext.size(),
            aad.data(), aad.size(),
            nullptr,  // nsec
            nonce.data(), _key.key.data()) != 0) {
        throw std::runtime_error("AEAD encrypt failed");
    }
    if (maclen != out.tag.v.size()) {
        throw std::runtime_error("AEAD tag size mismatch");
    }
    return out;
}

SecureAead::Ciphertext SecureAead::seal(std::span<const uint8_t> plaintext,
                                        std::span<const uint8_t> aad) {
    if (_seq == std::numeric_limits<uint64_t>::max()) {
        throw std::runtime_error("nonce/seq overflow");
    }
    auto res = seal_with_seq(plaintext, aad, _seq);
    _seq++;
    return res;
}

std::vector<uint8_t> SecureAead::open_with_nonce(std::span<const uint8_t> ct, Tag tag,
                                                 std::span<const uint8_t> aad,
                                                 const std::array<uint8_t, 24>& nonce) {
    ensure_sodium();
    std::vector<uint8_t> pt(ct.size());
    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            pt.data(), nullptr, ct.data(), ct.size(), tag.v.data(), aad.data(), aad.size(),
            nonce.data(), _key.key.data()) != 0) {
        throw std::runtime_error("AEAD auth failed");
    }
    return pt;
}

}  // namespace crypto_lib::aead
