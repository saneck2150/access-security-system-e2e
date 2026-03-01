#include <chrono>
#include <string>
#include <unordered_map>

#include <access_core/handle_frame.hpp>
#include <access_decision/access_store.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <gtest/gtest.h>
#include <key_manager/key_manager.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>
#include <sodium.h>

static uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

static key_manager::KeyManager makeKm() {
    key_manager::KeyManager::MasterKey mk{};
    for (size_t i = 0; i < mk.size(); ++i) {
        mk[i] = static_cast<uint8_t>(i);
    }
    return key_manager::KeyManager(mk, {.currentKeyVersion = 1, .allowPreviousKeyVersion = true});
}

// Simple mock store for tests
class MockStore final : public access_decision::IAccessStore {
  public:
    std::optional<std::string> roleForCardHmac(std::string_view) const override {
        return std::nullopt;
    }

    bool isAllowed(uint32_t, std::string_view) const override { return false; }

    uint32_t currentKeyVersionForReader(uint32_t) const override { return 1; }

    void upsertReader(uint32_t, uint32_t) override {}

    bool isReaderAllowedDoor(uint32_t, uint32_t) const override { return true; }

    void allowDoorForReader(uint32_t, uint32_t) override {}
};

TEST(FrameHandler, ReplayRejectedBeforeDecrypt) {
    ASSERT_GE(sodium_init(), 0);

    auto km = makeKm();
    MockStore store;

    protocol::packet::Header h;
    h.reader_id = 1;
    h.door_id = 2;
    h.ts_unix_ms = nowUnixMs();
    h.seq = 42;
    h.key_version = 1;

    crypto_lib::aead::SecureAead sender(km.deriveAeadKey(h.reader_id, h.key_version));
    h.nonce = sender.deriveNonce(h.seq);

    const auto aadVec = h.to_bytes();
    const std::span<const uint8_t> aad(aadVec.data(), aadVec.size());

    const std::string msg = "payload";
    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()),
        aad,
        h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    const auto bytesOk = protocol::frame::serialize(f);

    access_core::FrameHandler::ReplayWindowMap windows;
    access_core::FrameHandler handler(km, windows, &store);

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

    auto km = makeKm();
    MockStore store;

    access_core::FrameHandler::ReplayWindowMap windows;

    protocol::packet::Header h;
    h.reader_id = 7;
    h.door_id = 9;
    h.ts_unix_ms = nowUnixMs();
    h.seq = 100;
    h.key_version = 1;

    crypto_lib::aead::SecureAead sender(km.deriveAeadKey(h.reader_id, h.key_version));
    h.nonce = sender.deriveNonce(h.seq);

    access_core::FrameHandler handler(km, windows, &store);

    const auto aadVec = h.to_bytes();
    const std::span<const uint8_t> aad(aadVec.data(), aadVec.size());

    const std::string msg = "ok";
    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()),
        aad,
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
