#include "access_decision/engine.hpp"
#include "access_decision/access_store.hpp"
#include "access_decision/audit.hpp"
#include "access_decision/card_id_hasher.hpp"

#include <crypto_lib/secure_aead.hpp>
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

class InMemoryStore final : public access_decision::IAccessStore {
  public:
    void upsert_card(std::string card_hmac_hex, std::string role) {
        _card_to_role[std::move(card_hmac_hex)] = std::move(role);
    }

    void allow_role(uint32_t door_id, std::string role) {
        _door_allowed_roles[door_id].insert(std::move(role));
    }

    std::optional<std::string> role_for_card_hmac(std::string_view card_hmac_hex) const override {
        auto it = _card_to_role.find(std::string(card_hmac_hex));
        if (it == _card_to_role.end())
            return std::nullopt;
        return it->second;
    }

    bool is_allowed(uint32_t door_id, std::string_view role) const override {
        auto it = _door_allowed_roles.find(door_id);
        if (it == _door_allowed_roles.end())
            return false;
        return it->second.count(std::string(role)) != 0;
    }

  private:
    std::unordered_map<std::string, std::string> _card_to_role;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> _door_allowed_roles;
};

static std::vector<uint8_t> make_frame_bytes(crypto_lib::aead::SecureAead& sender,
                                             uint32_t reader_id, uint32_t door_id, uint64_t seq,
                                             const std::string& json_payload) {
    protocol::packet::Header h;
    h.reader_id = reader_id;
    h.door_id = door_id;
    h.ts_unix_ms = now_unix_ms();
    h.seq = seq;

    h.nonce = sender.derive_nonce(h.seq);
    const auto aad_vec = h.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const auto cipher = sender.seal_with_seq(
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

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());
    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server_aead(key);

    std::array<uint8_t, 32> pepper{};
    pepper.fill(0x11);
    access_decision::CardIdHasher hasher(pepper);

    InMemoryStore store;
    store.upsert_card(hasher.hmac_hex("CARD1"), "employee");
    store.allow_role(7, "employee");

    access_decision::InMemoryAuditLog audit;
    access_decision::DecisionEngine engine(&store, hasher, &audit);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes = make_frame_bytes(sender, 1, 7, 42, R"({"card_id":"CARD1","action":"open"})");
    const auto res = engine.handle_frame_bytes(bytes, server_aead, windows);

    EXPECT_TRUE(res.allow);
    EXPECT_EQ(res.reason, "ok");
    ASSERT_FALSE(audit.events().empty());
    EXPECT_TRUE(audit.events().back().allow);
}

TEST(DecisionEngine, ReplayDenied) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());
    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server_aead(key);

    std::array<uint8_t, 32> pepper{};
    pepper.fill(0x11);
    access_decision::CardIdHasher hasher(pepper);

    InMemoryStore store;
    store.upsert_card(hasher.hmac_hex("CARD1"), "employee");
    store.allow_role(7, "employee");

    access_decision::DecisionEngine engine(&store, hasher, nullptr);
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes = make_frame_bytes(sender, 1, 7, 42, R"({"card_id":"CARD1","action":"open"})");

    const auto r1 = engine.handle_frame_bytes(bytes, server_aead, windows);
    EXPECT_TRUE(r1.allow);

    const auto r2 = engine.handle_frame_bytes(bytes, server_aead, windows);
    EXPECT_FALSE(r2.allow);
    EXPECT_EQ(r2.reason, "replay");
}

TEST(DecisionEngine, UnknownCardDenied) {
    ASSERT_GE(sodium_init(), 0);

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());
    crypto_lib::aead::SecureAead sender(key);
    crypto_lib::aead::SecureAead server_aead(key);

    std::array<uint8_t, 32> pepper{};
    pepper.fill(0x11);
    access_decision::CardIdHasher hasher(pepper);

    InMemoryStore store;
    store.allow_role(7, "employee");

    access_decision::DecisionEngine engine(&store, hasher, nullptr);
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    const auto bytes = make_frame_bytes(sender, 1, 7, 42, R"({"card_id":"NOPE","action":"open"})");
    const auto r = engine.handle_frame_bytes(bytes, server_aead, windows);

    EXPECT_FALSE(r.allow);
    EXPECT_EQ(r.reason, "unknown_card");
}
