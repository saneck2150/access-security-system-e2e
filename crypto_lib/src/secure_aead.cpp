#include "crypto_lib/secure_aead.hpp"

#include <cstring>
#include <limits>

#include "crypto_lib/crypto_utils.hpp"

namespace crypto_lib::aead {

using crypto_lib::utils::le64;

SecureAead::SecureAead(const AeadKey& key, CipherMode mode) : _key(key), _cipherMode(mode) {
    randombytes_buf(_noncePrefix.data(), _noncePrefix.size());
}

std::array<uint8_t, 24> SecureAead::deriveNonce(uint64_t seq) const {
    std::array<uint8_t, 24> nonce{};
    if (_cipherMode == CipherMode::XChaCha20Poly1305) {
        // 16-byte prefix || 8-byte seq_le  (full 24 bytes used)
        std::memcpy(nonce.data(), _noncePrefix.data(), 16);
        le64(seq, nonce.data() + 16);
    } else {
        // ChaCha20: 4-byte prefix || 8-byte seq_le = 12 bytes (bytes 12-23 stay zero)
        std::memcpy(nonce.data(), _noncePrefix.data(), 4);
        le64(seq, nonce.data() + 4);
    }
    return nonce;
}

void SecureAead::encryptDetached(const std::span<const uint8_t>& plaintext,
    const std::span<const uint8_t>& aad,
    const std::array<uint8_t, 24>& nonce,
    Ciphertext& out) {
    unsigned long long maclen = 0;
    int rc = -1;

    if (_cipherMode == CipherMode::XChaCha20Poly1305) {
        rc = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(out.ct.data(),
            out.tag.v.data(),
            &maclen,
            plaintext.data(),
            plaintext.size(),
            aad.data(),
            aad.size(),
            nullptr,
            nonce.data(),
            _key.key.data());
    } else {
        // ChaCha20-Poly1305 IETF: uses first 12 bytes of nonce
        rc = crypto_aead_chacha20poly1305_ietf_encrypt_detached(out.ct.data(),
            out.tag.v.data(),
            &maclen,
            plaintext.data(),
            plaintext.size(),
            aad.data(),
            aad.size(),
            nullptr,
            nonce.data(),
            _key.key.data());
    }

    if (rc != 0) {
        throw std::runtime_error("AEAD encrypt failed");
    }
    if (maclen != out.tag.v.size()) {
        throw std::runtime_error("AEAD tag size mismatch");
    }
}

void SecureAead::decryptDetached(const std::span<const uint8_t>& ct,
    const Tag& tag,
    const std::span<const uint8_t>& aad,
    const std::array<uint8_t, 24>& nonce,
    std::vector<uint8_t>& out) {
    int rc = -1;

    if (_cipherMode == CipherMode::XChaCha20Poly1305) {
        rc = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(out.data(),
            nullptr,
            ct.data(),
            ct.size(),
            tag.v.data(),
            aad.data(),
            aad.size(),
            nonce.data(),
            _key.key.data());
    } else {
        // ChaCha20-Poly1305 IETF: uses first 12 bytes of nonce
        rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached(out.data(),
            nullptr,
            ct.data(),
            ct.size(),
            tag.v.data(),
            aad.data(),
            aad.size(),
            nonce.data(),
            _key.key.data());
    }

    if (rc != 0) {
        throw std::runtime_error("AEAD auth failed");
    }
}

SecureAead::Ciphertext SecureAead::sealWithSeq(
    std::span<const uint8_t> plaintext, std::span<const uint8_t> aad, uint64_t seq) {
    Ciphertext out;
    out.ct.resize(plaintext.size());
    out.nonce = deriveNonce(seq);

    encryptDetached(plaintext, aad, out.nonce, out);
    return out;
}

SecureAead::Ciphertext SecureAead::seal(
    std::span<const uint8_t> plaintext, std::span<const uint8_t> aad) {
    if (_seq == std::numeric_limits<uint64_t>::max()) {
        throw std::runtime_error("nonce/seq overflow");
    }
    auto result = sealWithSeq(plaintext, aad, _seq);
    _seq++;
    return result;
}

std::vector<uint8_t> SecureAead::openWithNonce(std::span<const uint8_t> ct,
    const Tag& tag,
    std::span<const uint8_t> aad,
    const std::array<uint8_t, 24>& nonce) {
    std::vector<uint8_t> plaintext(ct.size());
    decryptDetached(ct, tag, aad, nonce, plaintext);
    return plaintext;
}

}  // namespace crypto_lib::aead
