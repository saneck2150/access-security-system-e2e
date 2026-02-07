#include "crypto_lib/hkdf.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

TEST(HKDFTest, OutputLength) {
    std::vector<uint8_t> ikm = {1, 2, 3, 4, 5};
    std::vector<uint8_t> salt = {9, 8, 7};
    auto out = crypto_lib::hkdf::hkdf_sha256(ikm, salt, "ctx", 42);
    EXPECT_EQ(out.size(), 42u);
}

TEST(HKDFTest, Deterministic) {
    std::vector<uint8_t> ikm = {1, 2, 3, 4, 5};
    std::vector<uint8_t> salt = {9, 8, 7};
    auto a = crypto_lib::hkdf::hkdf_sha256(ikm, salt, "ctx", 32);
    auto b = crypto_lib::hkdf::hkdf_sha256(ikm, salt, "ctx", 32);
    EXPECT_EQ(a, b);
}
