#include <access_core/handle_frame.hpp>
#include <config_loader/config.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>

static uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
    const std::string cfgPath = (argc > 1) ? argv[1] : "config/access_security.yaml";

    config_loader::Config cfg;
    try {
        cfg = config_loader::loadFromYaml(cfgPath);
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
    header.ts_unix_ms = nowUnixMs();
    header.seq = 42;

    header.nonce = reader.deriveNonce(header.seq);

    const auto aadVec = header.to_bytes();
    const std::span<const uint8_t> aad(aadVec.data(), aadVec.size());

    const std::string plaintext = "card_id=CARD1;action=open";

    auto cipher = reader.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(plaintext.data()),
                                 plaintext.size()),
        aad, header.seq);

    header.nonce = cipher.nonce;

    protocol::frame::Frame fr;
    fr.header = header;
    fr.header.nonce = cipher.nonce;
    fr.ct = cipher.ct;
    fr.tag.v = cipher.tag.v;

    auto bytes = protocol::frame::serialize(fr);

    access_core::FrameHandler::ReplayWindowMap windows;
    access_core::FrameHandler handler(server, windows, cfg.frameHandler);

    auto r1 = handler.handle(bytes);
    std::cout << "FrameHandler #1: " << r1.reason << "\n";

    auto r2 = handler.handle(bytes);
    std::cout << "FrameHandler #2: " << r2.reason << "\n";

    return 0;
}