#include <access_storage/sqlite_access_store.hpp>
#include <access_storage/sqlite_audit_log.hpp>
#include <access_storage/audit_verify.hpp>

#include <access_decision/card_id_hasher.hpp>
#include <access_decision/engine.hpp>

#include <crypto_lib/secure_aead.hpp>
#include <key_manager/key_manager.hpp>
#include <protocol_lib/frame.hpp>

#include <gtest/gtest.h>
#include <sodium.h>
#include <sqlite3.h>

#include <array>
#include <chrono>
#include <unordered_map>

static uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

static std::vector<uint8_t> makeFrameBytes(crypto_lib::aead::SecureAead& sender, uint32_t readerId,
                                           uint32_t doorId, uint64_t seq, uint32_t keyVersion,
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
        aad, h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    return protocol::frame::serialize(f);
}

///@todo split into smaller tests + make mock
TEST(AuditChain, DetectsTampering) {
    ASSERT_GE(sodium_init(), 0);

    key_manager::KeyManager::MasterKey masterKey{};
    randombytes_buf(masterKey.data(), masterKey.size());
    key_manager::KeyManager keyManager(masterKey);

    const auto auditKey = keyManager.deriveAuditHmacKey();

    constexpr uint32_t readerId = 1;
    constexpr uint32_t keyVersion = 1;
    const auto aeadKey = keyManager.deriveAeadKey(readerId, keyVersion);
    crypto_lib::aead::SecureAead sender(aeadKey);

    // Use KeyManager-derived pepper for card HMAC
    const auto pepper = keyManager.deriveCardPepper(keyVersion);
    access_decision::CardIdHasher hasher(pepper);

    access_storage::SqliteAccessStore store(":memory:");
    store.initSchema();
    store.upsertReader(readerId, keyVersion);
    store.allowDoorForReader(readerId, 7);
    store.allowRole(7, "employee");

    const std::string cardHmac = hasher.hmacHex("CARD1");
    store.upsertCardHmac(cardHmac, "employee");

    access_storage::SqliteAuditLog audit(store.dbHandle(), auditKey);

    access_decision::DecisionEngine engine(&store, hasher, &audit, keyManager);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    // write 2 audit rows
    {
        const auto bytes = makeFrameBytes(sender, readerId, 7, 1, keyVersion,
                                          R"({"card_id":"CARD1","action":"open"})");
        const auto r = engine.handleFrameBytes(bytes, windows);
        ASSERT_TRUE(r.allow);
    }
    {
        const auto bytes = makeFrameBytes(sender, readerId, 7, 2, keyVersion,
                                          R"({"card_id":"NOPE","action":"open"})");
        const auto r = engine.handleFrameBytes(bytes, windows);
        ASSERT_FALSE(r.allow);
    }

    // should verify ok
    {
        const auto vr = access_storage::verifyAuditChain(store.dbHandle(), auditKey);
        EXPECT_TRUE(vr.ok) << vr.error;
    }

    // tamper with row 1
    {
        char* err = nullptr;
        const int rc = sqlite3_exec(store.dbHandle(),
            "UPDATE audit_log SET reason='TAMPERED' WHERE id=1;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "sqlite error";
            sqlite3_free(err);
            FAIL() << msg;
        }
    }

    {
        const auto vr = access_storage::verifyAuditChain(store.dbHandle(), auditKey);
        EXPECT_FALSE(vr.ok);
        EXPECT_EQ(vr.bad_id, 1);
    }
}
///@todo split into smaller tests + make mock
TEST(AuditChain, DetectsTruncation) {
    ASSERT_GE(sodium_init(), 0);

    key_manager::KeyManager::MasterKey masterKey{};
    randombytes_buf(masterKey.data(), masterKey.size());
    key_manager::KeyManager keyManager(masterKey);

    const auto auditKey = keyManager.deriveAuditHmacKey();

    constexpr uint32_t readerId = 1;
    constexpr uint32_t keyVersion = 1;
    const auto aeadKey = keyManager.deriveAeadKey(readerId, keyVersion);
    crypto_lib::aead::SecureAead sender(aeadKey);

    const auto pepper = keyManager.deriveCardPepper(keyVersion);
    access_decision::CardIdHasher hasher(pepper);

    access_storage::SqliteAccessStore store(":memory:");
    store.initSchema();
    store.upsertReader(readerId, keyVersion);
    store.allowDoorForReader(readerId, 7);
    store.allowRole(7, "employee");

    const std::string cardHmac = hasher.hmacHex("CARD1");
    store.upsertCardHmac(cardHmac, "employee");

    access_storage::SqliteAuditLog audit(store.dbHandle(), auditKey);

    access_decision::DecisionEngine engine(&store, hasher, &audit, keyManager);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    // Write 2 audit rows
    {
        const auto bytes = makeFrameBytes(sender, readerId, 7, 1, keyVersion,
                                          R"({"card_id":"CARD1","action":"open"})");
        const auto r = engine.handleFrameBytes(bytes, windows);
        ASSERT_TRUE(r.allow);
    }
    {
        const auto bytes = makeFrameBytes(sender, readerId, 7, 2, keyVersion,
                                          R"({"card_id":"CARD1","action":"open"})");
        const auto r = engine.handleFrameBytes(bytes, windows);
        ASSERT_TRUE(r.allow);
    }

    // Should verify ok before truncation
    {
        const auto vr = access_storage::verifyAuditChain(store.dbHandle(), auditKey);
        EXPECT_TRUE(vr.ok) << vr.error;
    }

    // Delete the last row (simulates truncation attack)
    {
        char* err = nullptr;
        const int rc = sqlite3_exec(store.dbHandle(),
            "DELETE FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log);",
            nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "sqlite error";
            sqlite3_free(err);
            FAIL() << msg;
        }
    }

    // Should detect anchor mismatch
    const auto vr = access_storage::verifyAuditChain(store.dbHandle(), auditKey);
    EXPECT_FALSE(vr.ok);
    EXPECT_NE(vr.error.find("anchor mismatch"), std::string::npos) << "actual error: " << vr.error;
}
