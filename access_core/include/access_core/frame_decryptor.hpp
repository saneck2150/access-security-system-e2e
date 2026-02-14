#pragma once

#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace access_core {

struct DecryptorConfig {
    uint64_t maxSkewMs = 0; // 0 = no timestamp check
};

struct DecryptResult {
    bool success = false;
    std::string error;
    std::vector<uint8_t> plaintext;
};

class FrameDecryptor {
  public:
    FrameDecryptor(crypto_lib::aead::SecureAead& aead, DecryptorConfig config = {});

    DecryptResult decrypt(const protocol::frame::Frame& frame);

  private:
    crypto_lib::aead::SecureAead& _aead;
    DecryptorConfig _config;

    std::vector<uint8_t> decryptFrame(const protocol::frame::Frame& frame);
    std::optional<std::string> checkTimestamp(uint64_t frameTimestamp) const;
    uint64_t nowUnixMs() const;
};

} // namespace access_core
