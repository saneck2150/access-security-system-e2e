#include "access_decision/engine.hpp"
#include "access_decision/access_store.hpp"
#include "access_decision/audit.hpp"
#include "access_decision/card_id_hasher.hpp"

#include <crypto_lib/secure_aead.hpp>
#include <key_manager/key_manager.hpp>
#include <protocol_lib/frame.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

static uint64_t now_unix_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

static key_manager::KeyManager makeKm() {
    key_manager::KeyManager::MasterKey mk{};
    for (size_t i = 0; i < mk.size(); ++i)
        mk[i] = static_cast<uint8_t>(i);
    return key_manager::KeyManager(mk, {.currentKeyVersion = 1, .allowPreviousKeyVersion = true});
}

/// @todo move to mock store file
class InMemoryStore final : public access_decision::IAccessStore {
  public:
    void upsertCard(std::string cardHmacHex, std::string role) {
        _cardToRole[std::move(cardHmacHex)] = std::move(role);
    }

    void allowRole(uint32_t doorId, std::string role) {
        _doorAllowedRoles[doorId].insert(std::move(role));
    }

    std::optional<std::string> roleForCardHmac(std::string_view cardHmacHex) const override {
        auto it = _cardToRole.find(std::string(cardHmacHex));
        if (it == _cardToRole.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool isAllowed(uint32_t doorId, std::string_view role) const override {
        auto it = _doorAllowedRoles.find(doorId);
        if (it == _doorAllowedRoles.end()) {
            return false;
        }
        return it->second.count(std::string(role)) != 0;
    }

    void allowDoorForReader(uint32_t reader_id, uint32_t door_id) override {
    _readerDoors[reader_id].insert(door_id);
    }

    bool isReaderAllowedDoor(uint32_t reader_id, uint32_t door_id) const override {
        auto it = _readerDoors.find(reader_id);
        if (it == _readerDoors.end()) return false;
        return it->second.count(door_id) != 0;
    }

    uint32_t currentKeyVersionForReader(uint32_t readerId) const override {
        auto it = _readerKeyVer.find(readerId);
        return (it == _readerKeyVer.end()) ? 0u : it->second;
    }

    void upsertReader(uint32_t readerId, uint32_t currentKeyVersion) override {
        _readerKeyVer[readerId] = currentKeyVersion;
    }

  private:
    std::unordered_map<std::string, std::string> _cardToRole;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> _doorAllowedRoles;
    std::unordered_map<uint32_t, uint32_t> _readerKeyVer;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>> _readerDoors;
};

static std::vector<uint8_t> make_frame_bytes(crypto_lib::aead::SecureAead& sender,
                                             uint32_t reader_id, uint32_t door_id, uint64_t seq,
                                             const std::string& json_payload) {
    protocol::packet::Header h;
    h.reader_id = reader_id;
    h.door_id = door_id;
    h.ts_unix_ms = now_unix_ms();
    h.seq = seq;
    h.key_version = 1;

    h.nonce = sender.deriveNonce(h.seq);
    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const auto cipher = sender.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(json_payload.data()),
                                 json_payload.size()),
        aad, h.seq);

    protocol::frame::Frame f;
    f.header = h;
    f.header.nonce = cipher.nonce;
    f.ct = cipher.ct;
    f.tag.v = cipher.tag.v;

    return protocol::frame::serialize(f);
}

TEST(DecisionEngine, AllowOk) {
    ASSERT_GE(sodium_init(), 0);

    auto km = makeKm();
    constexpr uint32_t readerId = 1;
    constexpr uint32_t keyVersion = 1;

    crypto_lib::aead::SecureAead sender(km.deriveAeadKey(readerId, keyVersion));

    // Use KeyManager-derived pepper for card HMAC
    const auto pepper = km.deriveCardPepper(keyVersion);
    access_decision::CardIdHasher hasher(pepper);

    InMemoryStore store;
    store.upsertCard(hasher.hmacHex("CARD1"), "employee");
    store.allowRole(7, "employee");
    store.upsertReader(readerId, keyVersion);
    store.allowDoorForReader(readerId, 7);

    access_decision::InMemoryAuditLog audit;
    access_decision::DecisionEngine engine(&store, hasher, &audit, km, {});

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes =
        make_frame_bytes(sender, readerId, 7, 42, R"({"card_id":"CARD1","action":"open"})");
    const auto res = engine.handleFrameBytes(bytes, windows);

    EXPECT_TRUE(res.allow);
    EXPECT_EQ(res.reason, "ok");
    ASSERT_FALSE(audit.events().empty());
    EXPECT_TRUE(audit.events().back().allow);
}

TEST(DecisionEngine, ReplayDenied) {
    ASSERT_GE(sodium_init(), 0);
    auto km = makeKm();
    constexpr uint32_t readerId = 1;
    constexpr uint32_t keyVersion = 1;

    crypto_lib::aead::SecureAead sender(km.deriveAeadKey(readerId, keyVersion));

    // Use KeyManager-derived pepper for card HMAC
    const auto pepper = km.deriveCardPepper(keyVersion);
    access_decision::CardIdHasher hasher(pepper);

    InMemoryStore store;
    store.upsertCard(hasher.hmacHex("CARD1"), "employee");
    store.allowRole(7, "employee");
    store.upsertReader(readerId, keyVersion);
    store.allowDoorForReader(readerId, 7);

    access_decision::DecisionEngine engine(&store, hasher, nullptr, km, {});
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes =
        make_frame_bytes(sender, readerId, 7, 42, R"({"card_id":"CARD1","action":"open"})");

    const auto r1 = engine.handleFrameBytes(bytes, windows);
    EXPECT_TRUE(r1.allow);

    const auto r2 = engine.handleFrameBytes(bytes, windows);
    EXPECT_FALSE(r2.allow);
    EXPECT_EQ(r2.reason, "replay");
}

TEST(DecisionEngine, UnknownCardDenied) {
    ASSERT_GE(sodium_init(), 0);

    auto km = makeKm();
    constexpr uint32_t readerId = 1;
    constexpr uint32_t keyVersion = 1;

    crypto_lib::aead::SecureAead sender(km.deriveAeadKey(readerId, keyVersion));

    // Use KeyManager-derived pepper for card HMAC
    const auto pepper = km.deriveCardPepper(keyVersion);
    access_decision::CardIdHasher hasher(pepper);

    InMemoryStore store;
    store.allowRole(7, "employee");
    store.upsertReader(readerId, keyVersion);
    store.allowDoorForReader(readerId, 7);

    access_decision::DecisionEngine engine(&store, hasher, nullptr, km, {});
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes =
        make_frame_bytes(sender, readerId, 7, 42, R"({"card_id":"NOPE","action":"open"})");
    const auto r = engine.handleFrameBytes(bytes, windows);

    EXPECT_FALSE(r.allow);
    EXPECT_EQ(r.reason, "unknown_card");
}

TEST(DecisionEngine, ReaderDoorForbidden) {
    ASSERT_GE(sodium_init(), 0);

    auto km = makeKm();
    constexpr uint32_t readerId = 1;
    constexpr uint32_t keyVersion = 1;

    crypto_lib::aead::SecureAead sender(km.deriveAeadKey(readerId, keyVersion));

    // Use KeyManager-derived pepper for card HMAC
    const auto pepper = km.deriveCardPepper(keyVersion);
    access_decision::CardIdHasher hasher(pepper);

    InMemoryStore store;
    store.upsertReader(readerId, keyVersion);
    // store.allowDoorForReader(readerId, 7);  // intentionally missing

    store.upsertCard(hasher.hmacHex("CARD1"), "employee");
    store.allowRole(7, "employee");

    access_decision::DecisionEngine engine(&store, hasher, nullptr, km, {});
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes =
        make_frame_bytes(sender, readerId, 7, 42, R"({"card_id":"CARD1","action":"open"})");

    const auto r = engine.handleFrameBytes(bytes, windows);
    EXPECT_FALSE(r.allow);
    EXPECT_EQ(r.reason, "reader_door_forbidden");
}
