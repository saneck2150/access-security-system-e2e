#include <access_core/handle_frame.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <chrono>
#include <string>
#include <unordered_map>

static uint64_t now_unix_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

TEST(HandleFrame, ReplayRejectedBeforeDecrypt) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server(key);

    protocol::packet::Header h;
    h.reader_id = 1;
    h.door_id = 2;
    h.ts_unix_ms = now_unix_ms();
    h.seq = 42;
    h.nonce = sender.derive_nonce(h.seq);

    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const std::string msg = "payload";
    const auto cipher = sender.seal_with_seq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()), aad,
        h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    const auto bytes_ok = protocol::frame::serialize(f);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    auto r1 = access_core::handle_frame(bytes_ok, server, windows);
    ASSERT_TRUE(r1.allow);
    ASSERT_EQ(r1.reason, "ok");
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(r1.plaintext.data()), r1.plaintext.size()),
              msg);

    auto bytes_bad = bytes_ok;
    bytes_bad.back() ^= 0xFF;

    auto r2 = access_core::handle_frame(bytes_bad, server, windows);
    EXPECT_FALSE(r2.allow);
    EXPECT_EQ(r2.reason, "replay");
}

TEST(HandleFrame, DecryptFailDoesNotPoisonReplayWindow) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server(key);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    protocol::packet::Header h;
    h.reader_id = 7;
    h.door_id = 9;
    h.ts_unix_ms = now_unix_ms();
    h.seq = 100;
    h.nonce = sender.derive_nonce(h.seq);

    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const std::string msg = "ok";
    const auto cipher = sender.seal_with_seq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()), aad,
        h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    auto bytes = protocol::frame::serialize(f);

    bytes.back() ^= 0xAA;

    auto r1 = access_core::handle_frame(bytes, server, windows);
    EXPECT_FALSE(r1.allow);
    EXPECT_EQ(r1.reason, "decrypt_failed");

    const auto bytes_ok = protocol::frame::serialize(f);
    auto r2 = access_core::handle_frame(bytes_ok, server, windows);
    EXPECT_TRUE(r2.allow);
    EXPECT_EQ(r2.reason, "ok");
}
