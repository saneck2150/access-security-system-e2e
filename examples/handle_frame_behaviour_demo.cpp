#include <access_core/handle_frame.hpp>
#include <config_loader/config.hpp>
#include <crypto_lib/secure_aead.hpp>
#include <key_manager/key_manager.hpp>
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
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");

    const std::string cfgPath = (argc > 1) ? argv[1] : "../config/access_security.yaml";
    auto cfg = config_loader::loadFromYaml(cfgPath);

    /// @note
    // reader sending a frame to the server simulation
    // (in prod, reader and server are separate programs, here we do both sides in one place for
    // demo)
    auto master = key_manager::KeyManager::loadMasterKeyHexFile("../secrets/master_key.hex");
    key_manager::KeyManager km(master, {.currentKeyVersion = 1, .allowPreviousKeyVersion = true});

    protocol::packet::Header header;
    header.reader_id = 123;
    header.door_id = 7;
    header.ts_unix_ms = nowUnixMs();
    header.seq = 42;
    header.key_version = 1;

    const auto aeadKey = km.deriveAeadKey(header.reader_id, header.key_version);
    crypto_lib::aead::SecureAead reader(aeadKey);

    header.nonce = reader.deriveNonce(header.seq);
    const auto aadVec = header.to_bytes();
    const std::span<const uint8_t> aad(aadVec.data(), aadVec.size());

    const std::string plaintext = R"({"card_id":"CARD1","action":"open"})";
    auto cipher = reader.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(plaintext.data()),
                                 plaintext.size()),
        aad, header.seq);

    protocol::frame::Frame fr;
    fr.header = header;
    fr.header.nonce = cipher.nonce;
    fr.ct = cipher.ct;
    fr.tag.v = cipher.tag.v;

    auto bytes = protocol::frame::serialize(fr);

    access_core::FrameHandler::ReplayWindowMap windows;
    access_core::FrameHandler handler(km, windows, cfg.frameHandler);

    auto r1 = handler.handle(bytes);
    std::cout << "FrameHandler #1: " << r1.reason << "\n";

    auto r2 = handler.handle(bytes);
    std::cout << "FrameHandler #2: " << r2.reason << "\n";
}