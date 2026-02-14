#pragma once

#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/packet.hpp>

#include <chrono>
#include <span>
#include <vector>

namespace session {
class SecureFrameSession {
  public:
    SecureFrameSession(const protocol::packet::Header& header, const std::string& textToCipher);
    std::vector<uint8_t> getDecryptedText();

  private:
    // flags
    bool _isKeyGenerated = false;

    // actors
    crypto_lib::aead::AeadKey _key;
    crypto_lib::aead::SecureAead _reader;
    crypto_lib::aead::SecureAead _server;
    protocol::packet::Header _header;
    std::vector<uint8_t> _aadVec;
    const std::span<const uint8_t> _aad;
    crypto_lib::aead::SecureAead::Ciphertext _cipher;

    // functions
    bool generateKey();
    crypto_lib::aead::SecureAead::Ciphertext encryptFrame(const std::string& textToCipher);
};
} // namespace session