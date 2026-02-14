#pragma once

#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace crypto_lib::aead {

struct AeadKey {
    std::array<uint8_t, 32> key{};
};

struct Tag {
    std::array<uint8_t, 16> v{};
};

class SecureAead {
  public:
    struct Ciphertext {
        std::vector<uint8_t> ct;
        Tag tag;
        std::array<uint8_t, 24> nonce;
    };

    explicit SecureAead(const AeadKey& key);

    // encryption
    Ciphertext seal(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad);
    Ciphertext sealWithSeq(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad,
                           uint64_t seq);

    // decryption
    std::vector<uint8_t> openWithNonce(std::span<const uint8_t> ct, const Tag& tag,
                                       std::span<const uint8_t> aad,
                                       const std::array<uint8_t, 24>& nonce);

    std::array<uint8_t, 24> deriveNonce(uint64_t seq) const;

  private:
    AeadKey _key;
    std::array<uint8_t, 16> _noncePrefix{};
    uint64_t _seq = 0;

    void encryptDetached(const std::span<const uint8_t>& plaintext,
                         const std::span<const uint8_t>& aad, const std::array<uint8_t, 24>& nonce,
                         Ciphertext& out);

    void decryptDetached(const std::span<const uint8_t>& ct, const Tag& tag,
                         const std::span<const uint8_t>& aad, const std::array<uint8_t, 24>& nonce,
                         std::vector<uint8_t>& out);
};

} // namespace crypto_lib::aead
