#pragma once

//! @file scenario_common.hpp
//! Shared constants and helpers for all experiment scenarios.

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <crypto_lib/nonce_generator.hpp>
#include <key_manager/key_manager.hpp>

#include "experiments/frame_factory.hpp"

namespace experiments {

//! Deterministic master key: bytes 0..31.
key_manager::KeyManager::MasterKey makeMasterKey();

//! Converts a uint64_t seed to a 32-byte array (little-endian, zero-padded).
std::array<uint8_t, 32> seedToArray(uint64_t seed);

//! Returns the 6 standard profiles: A1-R0, A1-R1, A1-R2, A2-R0, A2-R1, A2-R2.
std::vector<ProfileConfig> allProfiles();

//! Creates the nonce generator for a profile.
//! Random profiles use SeededNonceGenerator(seed); deterministic use HmacNonceGenerator.
//! @param [in] readerId Reader ID for HMAC key derivation.
//! @param [in] keyVersion Key version for HMAC key derivation.
std::unique_ptr<crypto_lib::nonce::INonceGenerator> makeNonceGen(
    const ProfileConfig& profile,
    const key_manager::KeyManager& km,
    uint64_t seed,
    uint32_t readerId,
    uint32_t keyVersion);

}  // namespace experiments
