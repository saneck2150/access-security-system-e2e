#include "startup/secure_frame_session.hpp"

using namespace session;

SecureFrameSession::SecureFrameSession(const protocol::packet::Header& header,
                                       const std::string& textToCipher)
    : _isKeyGenerated(generateKey()),
      _reader(_key),
      _server(_key),
      _header(header),
      _aadVec(header.to_bytes()),
      _aad(_aadVec.data(), _aadVec.size()),
      _cipher(encryptFrame(textToCipher)) {}

bool SecureFrameSession::generateKey() {
    randombytes_buf(_key.key.data(), _key.key.size());
    return true;
}

crypto_lib::aead::SecureAead::Ciphertext SecureFrameSession::encryptFrame(
    const std::string& textToCipher) {
    return _reader.sealWithSeq(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(textToCipher.data()),
                                 textToCipher.size()),
        _aad, _header.seq);
}

std::vector<uint8_t> SecureFrameSession::getDecryptedText() {
    return _server.openWithNonce(_cipher.ct, _cipher.tag, _aad, _cipher.nonce);
}