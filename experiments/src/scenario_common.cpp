#include "experiments/scenario_common.hpp"

#include "experiments/seeded_nonce_generator.hpp"

namespace experiments {

key_manager::KeyManager::MasterKey makeMasterKey() {
    key_manager::KeyManager::MasterKey mk{};
    for (size_t i = 0; i < mk.size(); ++i) {
        mk[i] = static_cast<uint8_t>(i);
    }
    return mk;
}

std::array<uint8_t, 32> seedToArray(uint64_t seed) {
    std::array<uint8_t, 32> arr{};
    for (size_t i = 0; i < sizeof(seed); ++i) {
        arr[i] = static_cast<uint8_t>(seed >> (i * 8));
    }
    return arr;
}

std::vector<ProfileConfig> allProfiles() {
    return {
        {"A1-R0", "chacha20", "random", "hkdf", "full", "versioned", false, 100, 5},
        {"A1-R1", "chacha20", "deterministic", "hkdf", "full", "versioned", false, 100, 5},
        {"A1-R2", "chacha20", "deterministic", "hkdf", "full", "versioned", true, 100, 5},
        {"A2-R0", "xchacha20", "random", "hkdf", "full", "versioned", false, 100, 5},
        {"A2-R1", "xchacha20", "deterministic", "hkdf", "full", "versioned", false, 100, 5},
        {"A2-R2", "xchacha20", "deterministic", "hkdf", "full", "versioned", true, 100, 5},
    };
}

std::unique_ptr<crypto_lib::nonce::INonceGenerator> makeNonceGen(
    const ProfileConfig& profile,
    const key_manager::KeyManager& km,
    uint64_t seed,
    uint32_t readerId,
    uint32_t keyVersion) {
    auto cm = (profile.cipherMode == "chacha20")
                  ? crypto_lib::aead::CipherMode::ChaCha20Poly1305
                  : crypto_lib::aead::CipherMode::XChaCha20Poly1305;
    if (profile.nonceMode == "random") {
        return std::make_unique<SeededNonceGenerator>(seedToArray(seed), cm);
    }
    return std::make_unique<crypto_lib::nonce::HmacNonceGenerator>(
        km.deriveNonceKey(readerId, keyVersion), cm);
}

}  // namespace experiments
