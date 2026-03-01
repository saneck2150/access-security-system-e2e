#include <array>
#include <chrono>
#include <unordered_map>

#include <access_decision/audit.hpp>
#include <access_decision/card_id_hasher.hpp>
#include <access_decision/engine.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <gtest/gtest.h>
#include <key_manager/key_manager.hpp>
#include <protocol_lib/frame.hpp>
#include <sodium.h>

#include "access_storage/sqlite_access_store.hpp"

static uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

static std::vector<uint8_t> makeFrameBytes(crypto_lib::aead::SecureAead& sender,
                                           uint32_t readerId,
                                           uint32_t doorId,
                                           uint64_t seq,
                                           uint32_t keyVersion,
                                           const std::string& jsonPayload) {
    protocol::packet::Header h;
    h.reader_id = readerId;
    h.door_id = doorId;
    h.ts_unix_ms = nowUnixMs();
    h.seq = seq;
    h.key_version = keyVersion;

    h.nonce = sender.deriveNonce(h.seq);
    const auto aadVec = h.to_bytes();
    const std::span<const uint8_t> aad(aadVec.data(), aadVec.size());

    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(jsonPayload.data()),
                                 jsonPayload.size()),
        aad,
        h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    return protocol::frame::serialize(f);
}

TEST(DecisionEngineSqlite, AllowOkWithHmacLookup) {
    ASSERT_GE(sodium_init(), 0);

    key_manager::KeyManager::MasterKey masterKey{};
    randombytes_buf(masterKey.data(), masterKey.size());
    key_manager::KeyManager keyManager(masterKey);

    constexpr uint32_t readerId = 1;
    constexpr uint32_t keyVersion = 1;
    const auto aeadKey = keyManager.deriveAeadKey(readerId, keyVersion);
    crypto_lib::aead::SecureAead sender(aeadKey);

    // Use KeyManager-derived pepper for card HMAC
    const auto pepper = keyManager.deriveCardPepper(keyVersion);
    access_decision::CardIdHasher hasher(pepper);

    access_storage::SqliteAccessStore store(":memory:");
    store.initSchema();

    const std::string cardId = "CARD1";
    const std::string cardHmac = hasher.hmacHex(cardId);
    store.upsertCardHmac(cardHmac, "employee");
    store.allowRole(7, "employee");
    store.upsertReader(readerId, keyVersion);  // Register reader with key version
    store.allowDoorForReader(readerId, 7);

    access_decision::InMemoryAuditLog audit;
    access_decision::DecisionEngine engine(&store, hasher, &audit, keyManager);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes = makeFrameBytes(
        sender, readerId, 7, 42, keyVersion, R"({"card_id":"CARD1","action":"open"})");
    const auto res = engine.handleFrameBytes(bytes, windows);

    EXPECT_TRUE(res.allow);
    EXPECT_EQ(res.reason, "ok");
}
