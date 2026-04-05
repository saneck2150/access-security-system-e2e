#include "experiments/seeded_nonce_generator.hpp"

#include <cstring>

#include <sodium.h>

namespace experiments {

SeededNonceGenerator::SeededNonceGenerator(
    const std::array<uint8_t, 32>& seed,
    crypto_lib::aead::CipherMode cipherMode)
    : _seed(seed),
      _nonceLen(crypto_lib::nonce::nonceLenFor(cipherMode)) {}

std::array<uint8_t, 24> SeededNonceGenerator::generate(
    std::span<const uint8_t> /*context*/, uint64_t seq) {
    // Derive nonce = ChaCha20(key=seed, nonce=seq_le_padded, counter=0) applied to zeros.
    // This makes nonce a pure function of (seed, seq).
    std::array<uint8_t, 24> nonce{};

    // Use seq as the 12-byte IETF nonce for the ChaCha20 stream.
    std::array<uint8_t, 12> streamNonce{};
    std::memcpy(streamNonce.data(), &seq, sizeof(seq));

    // Generate _nonceLen bytes of keystream.
    // crypto_stream_chacha20_ietf produces keystream; we XOR with zeros → keystream itself.
    std::array<uint8_t, 24> zeros{};
    crypto_stream_chacha20_ietf_xor_ic(
        nonce.data(), zeros.data(), _nonceLen,
        streamNonce.data(), 0, _seed.data());

    return nonce;
}

}  // namespace experiments
