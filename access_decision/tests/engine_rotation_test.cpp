#include <gtest/gtest.h>
#include <sodium.h>

#include <access_decision/engine.hpp>
#include <access_decision/audit.hpp>
#include <access_decision/card_id_hasher.hpp>

#include <access_storage/sqlite_access_store.hpp>
#include <key_manager/key_manager.hpp>

#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

#include <unordered_map>
#include <chrono>

static uint64_t now_unix_ms() {
  using namespace std::chrono;
  return static_cast<uint64_t>(
      duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

static std::vector<uint8_t> make_frame_bytes(const key_manager::KeyManager& km,
                                             uint32_t reader_id,
                                             uint32_t door_id,
                                             uint64_t seq,
                                             uint32_t key_version,
                                             const std::string& json_payload) {
  protocol::packet::Header h;
  h.reader_id = reader_id;
  h.door_id = door_id;
  h.ts_unix_ms = now_unix_ms();
  h.seq = seq;
  h.key_version = key_version;

  crypto_lib::aead::SecureAead sender(km.deriveAeadKey(reader_id, key_version));
  h.nonce = sender.deriveNonce(h.seq);

  const auto aad_vec = h.to_bytes();
  const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

  const auto cipher = sender.sealWithSeq(
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(json_payload.data()), json_payload.size()),
      aad,
      h.seq);

  protocol::frame::Frame f;
  f.header = h;
  f.header.nonce = cipher.nonce;
  f.ct = cipher.ct;
  f.tag.v = cipher.tag.v;

  return protocol::frame::serialize(f);
}

TEST(KeyRotation, AcceptCurrentAndPrevious) {
  ASSERT_GE(sodium_init(), 0);

  // master key fixed for test
  key_manager::KeyManager::MasterKey mk{};
  for (size_t i = 0; i < mk.size(); ++i) mk[i] = static_cast<uint8_t>(i);
  key_manager::KeyManager km(mk, {.currentKeyVersion = 999, .allowPreviousKeyVersion = true}); // global cfg unused here

  // SQLite store in memory
  access_storage::SqliteAccessStore store(":memory:");
  store.initSchema();

  // reader policy: current=2
  store.upsertReader(10, 2);
  store.allowDoorForReader(10, 7);

  // HMAC setup
  std::array<uint8_t, 32> pepper{};
  pepper.fill(0x11);
  access_decision::CardIdHasher hasher(pepper);

  // allow
  store.allowRole(7, "employee");
  store.upsertCardHmac(hasher.hmacHex("CARD1"), "employee");

  access_decision::InMemoryAuditLog audit;

  access_core::FrameHandlerConfig fh_cfg;
  fh_cfg.allowPreviousKeyVersion = true;
  fh_cfg.maxSkewMs = 0; 

  access_decision::DecisionEngine engine(&store, hasher, &audit, km, fh_cfg);

  std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

  const auto ok_v2 = make_frame_bytes(km, 10, 7, 1, 2, R"({"card_id":"CARD1","action":"open"})");
  const auto r2 = engine.handleFrameBytes(ok_v2, windows);
  EXPECT_TRUE(r2.allow);

  const auto ok_v1 = make_frame_bytes(km, 10, 7, 2, 1, R"({"card_id":"CARD1","action":"open"})");
  const auto r1 = engine.handleFrameBytes(ok_v1, windows);
  EXPECT_TRUE(r1.allow);

  const auto bad_v3 = make_frame_bytes(km, 10, 7, 3, 3, R"({"card_id":"CARD1","action":"open"})");
  const auto r3 = engine.handleFrameBytes(bad_v3, windows);
  EXPECT_FALSE(r3.allow);
  EXPECT_EQ(r3.reason, "bad_key_version");
}
