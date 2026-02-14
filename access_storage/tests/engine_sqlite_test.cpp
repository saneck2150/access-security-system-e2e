#include "access_storage/sqlite_access_store.hpp"

#include <access_decision/audit.hpp>
#include <access_decision/card_id_hasher.hpp>
#include <access_decision/engine.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>

#include <gtest/gtest.h>
#include <sodium.h>
#include <array>
#include <chrono>
#include <unordered_map>

static uint64_t now_unix_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

static std::vector<uint8_t> make_frame_bytes(crypto_lib::aead::SecureAead& sender,
                                             uint32_t reader_id, uint32_t door_id, uint64_t seq,
                                             const std::string& json_payload) {
    protocol::packet::Header h;
    h.reader_id = reader_id;
    h.door_id = door_id;
    h.ts_unix_ms = now_unix_ms();
    h.seq = seq;

    h.nonce = sender.deriveNonce(h.seq);
    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>((const uint8_t*)json_payload.data(), json_payload.size()), aad,
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

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());
    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server_aead(key);

    std::array<uint8_t, 32> pepper{};
    pepper.fill(0x11);
    access_decision::CardIdHasher hasher(pepper);

    access_storage::SqliteAccessStore store(":memory:");
    store.initSchema();

    const std::string cardId = "CARD1";
    const std::string cardHmac = hasher.hmacHex(cardId);
    store.upsertCardHmac(cardHmac, "employee");
    store.allowRole(7, "employee");

    access_decision::InMemoryAuditLog audit;
    access_decision::DecisionEngine engine(&store, hasher, &audit);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes = make_frame_bytes(sender, 1, 7, 42, R"({"card_id":"CARD1","action":"open"})");
    const auto res = engine.handleFrameBytes(bytes, server_aead, windows);

    EXPECT_TRUE(res.allow);
    EXPECT_EQ(res.reason, "ok");
}
