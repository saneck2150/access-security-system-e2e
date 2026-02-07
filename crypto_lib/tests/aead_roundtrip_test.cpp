#include "crypto_lib/secure_aead.hpp"

#include <protocol_lib/packet.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <chrono>
#include <string>

static uint64_t now_unix_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

TEST(AeadRoundtrip, RoundtripOk) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead receiver(key);

    protocol::packet::Header h;
    h.reader_id = 1;
    h.door_id = 2;
    h.ts_unix_ms = now_unix_ms();
    h.seq = 42;

    h.nonce = sender.derive_nonce(h.seq);

    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const std::string msg = "hello";
    const auto cipher = sender.seal_with_seq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()), aad,
        h.seq);

    h.nonce = cipher.nonce;

    const auto pt = receiver.open_with_nonce(cipher.ct, cipher.tag, aad, h.nonce);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(pt.data()), pt.size()), msg);
}

TEST(AeadRoundtrip, TamperDoorIdFails) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead receiver(key);

    protocol::packet::Header h;
    h.reader_id = 1;
    h.door_id = 2;
    h.ts_unix_ms = now_unix_ms();
    h.seq = 42;
    h.nonce = sender.derive_nonce(h.seq);

    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const std::string msg = "hello";
    const auto cipher = sender.seal_with_seq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()), aad,
        h.seq);

    protocol::packet::Header h2 = h;
    h2.nonce = cipher.nonce;
    h2.door_id = 999;

    const auto aad2_vec = h2.to_bytes();
    const std::span<const uint8_t> aad2(aad2_vec.data(), aad2_vec.size());

    EXPECT_THROW((void)receiver.open_with_nonce(cipher.ct, cipher.tag, aad2, h2.nonce),
                 std::runtime_error);
}

TEST(AeadRoundtrip, SameNonceDifferentAadFails) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead receiver(key);

    protocol::packet::Header h1;
    h1.reader_id = 10;
    h1.door_id = 20;
    h1.ts_unix_ms = now_unix_ms();
    h1.seq = 42;
    h1.nonce = sender.derive_nonce(h1.seq);

    const auto aad1_vec = h1.to_bytes();
    const std::span<const uint8_t> aad1(aad1_vec.data(), aad1_vec.size());

    const std::string msg = "payload";
    const auto cipher = sender.seal_with_seq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()), aad1,
        h1.seq);

    protocol::packet::Header h2 = h1;
    h2.nonce = cipher.nonce;
    h2.reader_id = 999;

    const auto aad2_vec = h2.to_bytes();
    const std::span<const uint8_t> aad2(aad2_vec.data(), aad2_vec.size());

    EXPECT_THROW((void)receiver.open_with_nonce(cipher.ct, cipher.tag, aad2, h2.nonce),
                 std::runtime_error);
}
