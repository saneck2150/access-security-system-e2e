#include <config_loader/config.hpp>
#include <access_core/handle_frame.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>

static uint64_t now_unix_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

int main(int argc, char** argv) {
    const std::string cfg_path = "../config/access_security.yaml";

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    config_loader::Config cfg;
    try {
        cfg = config_loader::load_from_yaml(cfg_path);
    } catch (const std::exception& e) {
        std::cerr << "Config load failed: " << e.what() << "\n";
        return 2;
    }

    crypto_lib::aead::AeadKey key;
    randombytes_buf(key.key.data(), key.key.size());

    crypto_lib::aead::SecureAead reader(key);
    crypto_lib::aead::SecureAead server(key);

    protocol::packet::Header header;
    header.reader_id = 123;
    header.door_id = 7;
    header.ts_unix_ms = now_unix_ms();
    header.seq = 42;

    header.nonce = reader.derive_nonce(header.seq);

    const auto aad_vec = header.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    const std::string plaintext = "card_id=CARD1;action=open";

    auto cipher = reader.seal_with_seq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(plaintext.data()),
                                 plaintext.size()),
        aad,
        header.seq);

    header.nonce = cipher.nonce;

    protocol::frame::Frame fr;
    fr.header = header;
    fr.header.nonce = cipher.nonce;
    fr.ct = cipher.ct;
    fr.tag.v = cipher.tag.v;

    auto bytes = protocol::frame::serialize(fr);

    std::unordered_map<uint32_t, protocol::replay::ReplayWindow> windows;

    auto r1 = access_core::handle_frame(bytes, server, windows, cfg.handle_frame);
    std::cout << "handle_frame #1: " << r1.reason << "\n";

    auto r2 = access_core::handle_frame(bytes, server, windows, cfg.handle_frame);
    std::cout << "handle_frame #2: " << r2.reason << "\n";

    return 0;
}