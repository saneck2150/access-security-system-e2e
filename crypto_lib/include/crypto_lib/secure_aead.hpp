#pragma once
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
    explicit SecureAead(AeadKey k);

    struct Ciphertext {
        std::vector<uint8_t> ct;
        Tag tag;
        std::array<uint8_t, 24> nonce;
    };

    Ciphertext seal(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad);


    Ciphertext seal_with_seq(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad,
                             uint64_t seq);

    std::vector<uint8_t> open_with_nonce(std::span<const uint8_t> ct, Tag tag,
                                         std::span<const uint8_t> aad,
                                         const std::array<uint8_t, 24>& nonce);

    std::array<uint8_t, 24> derive_nonce(uint64_t seq) const;

    std::vector<uint8_t> open(std::span<const uint8_t>, Tag, std::span<const uint8_t>) {
        throw std::logic_error("Use open_with_nonce(...). Nonce is required.");
    }

    /// @todo Proper inicialization process
    /// https://saneck2150-1760865460652.atlassian.net/browse/DIP-41?atlOrigin=eyJpIjoiN2Y3M2U0NTRlZTBhNDFhMTk2ZTY5NGQ1NzI5ZWM0NmYiLCJwIjoiaiJ9
    void ensure_sodium();

  private:
    AeadKey _key;
    uint64_t _seq = 0;
    std::array<uint8_t, 16> _noncePrefix{};

    /// @todo Proper inicialization process
    /// https://saneck2150-1760865460652.atlassian.net/browse/DIP-41?atlOrigin=eyJpIjoiN2Y3M2U0NTRlZTBhNDFhMTk2ZTY5NGQ1NzI5ZWM0NmYiLCJwIjoiaiJ9
    static bool _sodiumInitialized;
};

}  // namespace crypto_lib::aead
