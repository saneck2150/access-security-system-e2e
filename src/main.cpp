#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/packet.hpp>

#include <sodium.h>

#include <chrono>
#include <iostream>
#include <string>

static uint64_t now_unix_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

int main() {
    /// @todo Proper inicialization process
    /// https://saneck2150-1760865460652.atlassian.net/browse/DIP-41?atlOrigin=eyJpIjoiN2Y3M2U0NTRlZTBhNDFhMTk2ZTY5NGQ1NzI5ZWM0NmYiLCJwIjoiaiJ9
    if (sodium_init() < 0)
        return 1;
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

    const std::string plaintext = "card_id=ABC123;action=open";
    const auto cipher = reader.seal_with_seq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(plaintext.data()),
                                 plaintext.size()),
        aad, header.seq);

    header.nonce = cipher.nonce;

    const auto pt = server.open_with_nonce(cipher.ct, cipher.tag, aad, header.nonce);
    const std::string plaintext2(reinterpret_cast<const char*>(pt.data()), pt.size());

    if (plaintext2 != plaintext) {
        std::cerr << "E2E FAILED\n";
        return 2;
    }

    std::cout << "E2E OK: " << plaintext2 << "\n";
    return 0;
}