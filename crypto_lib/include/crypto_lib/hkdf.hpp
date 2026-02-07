#pragma once
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto_lib::hkdf {

std::vector<uint8_t> hkdf_sha256(std::span<const uint8_t> ikm, std::span<const uint8_t> salt,
                                 std::string_view info, size_t out_len);

}  // namespace crypto_lib::hkdf