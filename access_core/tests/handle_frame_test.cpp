#include <access_core/handle_frame.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <chrono>
#include <string>
#include <unordered_map>

static uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

TEST(FrameHandler, ReplayRejectedBeforeDecrypt) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server(key);

    protocol::packet::Header h;
    h.reader_id = 1;
    h.door_id = 2;
    h.ts_unix_ms = nowUnixMs();
    h.seq = 42;
    h.nonce = sender.deriveNonce(h.seq);

    const auto aadVec = h.to_bytes();
    const std::span<const uint8_t> aad(aadVec.data(), aadVec.size());

    const std::string msg = "payload";
    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()), aad,
        h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    const auto bytesOk = protocol::frame::serialize(f);

    access_core::FrameHandler::ReplayWindowMap windows;
    access_core::FrameHandler handler(server, windows);

    auto r1 = handler.handle(bytesOk);
    ASSERT_TRUE(r1.allow);
    ASSERT_EQ(r1.reason, "ok");
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(r1.plaintext.data()), r1.plaintext.size()),
              msg);

    auto bytesBad = bytesOk;
    bytesBad.back() ^= 0xFF;

    auto r2 = handler.handle(bytesBad);
    EXPECT_FALSE(r2.allow);
    EXPECT_EQ(r2.reason, "replay");
}

TEST(FrameHandler, DecryptFailDoesNotPoisonReplayWindow) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server(key);

    access_core::FrameHandler::ReplayWindowMap windows;
    access_core::FrameHandler handler(server, windows);

    protocol::packet::Header h;
    h.reader_id = 7;
    h.door_id = 9;
    h.ts_unix_ms = nowUnixMs();
    h.seq = 100;
    h.nonce = sender.deriveNonce(h.seq);

    const auto aadVec = h.to_bytes();
    const std::span<const uint8_t> aad(aadVec.data(), aadVec.size());

    const std::string msg = "ok";
    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()), aad,
        h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    auto bytes = protocol::frame::serialize(f);

    bytes.back() ^= 0xAA;

    auto r1 = handler.handle(bytes);
    EXPECT_FALSE(r1.allow);
    EXPECT_EQ(r1.reason, "decrypt_failed");

    const auto bytesOk = protocol::frame::serialize(f);
    auto r2 = handler.handle(bytesOk);
    EXPECT_TRUE(r2.allow);
    EXPECT_EQ(r2.reason, "ok");
}
