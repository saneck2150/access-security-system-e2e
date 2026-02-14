#include "crypto_lib/hkdf.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

TEST(HKDFTest, OutputLength) {
    std::vector<uint8_t> ikm = {1, 2, 3, 4, 5};
    std::vector<uint8_t> salt = {9, 8, 7};
    crypto_lib::hkdf::Hkdf hkdf(ikm, salt, "ctx", 42);
    auto out = hkdf.derive();
    EXPECT_EQ(out.size(), 42u);
}

TEST(HKDFTest, Deterministic) {
    std::vector<uint8_t> ikm = {1, 2, 3, 4, 5};
    std::vector<uint8_t> salt = {9, 8, 7};
    crypto_lib::hkdf::Hkdf hkdf1(ikm, salt, "ctx", 32);
    crypto_lib::hkdf::Hkdf hkdf2(ikm, salt, "ctx", 32);
    auto a = hkdf1.derive();
    auto b = hkdf2.derive();
    EXPECT_EQ(a, b);
}
