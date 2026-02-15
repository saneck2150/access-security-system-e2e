#include <protocol_lib/packet.hpp>
#include <startup/secure_frame_session.hpp>

#include <chrono>
#include <iostream>
#include <string>

static uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void sodiumInitOrThrow() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

int main() {
    sodiumInitOrThrow();
    ///@note Card scanner output:
    const std::string textToCipher = "card_id=ABC123;action=open";

    protocol::packet::Header header;
    header.reader_id = 123;
    header.door_id = 7;
    header.ts_unix_ms = nowUnixMs();
    header.seq = 42;
    header.key_version = 1;
    //////////////////////////////////////////////////////////////

    session::SecureFrameSession init(header, textToCipher);

    const auto pt = init.getDecryptedText();
    const std::string decryptedText(reinterpret_cast<const char*>(pt.data()), pt.size());

    if (decryptedText != textToCipher) {
        std::cerr << "E2E FAILED\n";
        return 2;
    }

    std::cout << "E2E OK: " << decryptedText << "\n";
    return 0;
}