#include <key_manager/key_manager.hpp>

#include <fstream>
#include <stdexcept>
#include <string>
#include <cctype>

namespace key_manager {

namespace {
/// @todo move to _utils cpp/hpp 
uint8_t hexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + (c - 'A'));
    throw std::invalid_argument("KeyManager: invalid hex char");
}

KeyManager::MasterKey parseHexKey(std::string_view s) {
    std::string hex;
    hex.reserve(s.size());
    for (char ch : s) {
        if (!std::isspace(static_cast<unsigned char>(ch))) hex.push_back(ch);
    }

    if (hex.size() != 64) {
        throw std::invalid_argument("KeyManager: master key hex must be 64 chars (32 bytes)");
    }

    KeyManager::MasterKey out{};
    for (size_t i = 0; i < out.size(); ++i) {
        const uint8_t hi = hexNibble(hex[2 * i]);
        const uint8_t lo = hexNibble(hex[2 * i + 1]);
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

}  // namespace

KeyManager::KeyManager(MasterKey masterKey, KeyManagerConfig cfg)
    : _masterKey(masterKey), _cfg(cfg) {
    if (_cfg.currentKeyVersion == 0) {
        throw std::invalid_argument("KeyManager: currentKeyVersion must be > 0");
    }
}

void KeyManager::putLe32(uint32_t v, uint8_t out[4]) const {
    out[0] = static_cast<uint8_t>(v & 0xff);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    out[3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

KeyManager::MasterKey KeyManager::loadMasterKeyHexFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("KeyManager: failed to open master key file: " + path);
    }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return parseHexKey(content);
}

bool KeyManager::isAcceptedKeyVersion(uint32_t keyVersion) const {
    if (keyVersion == 0) return false;
    if (keyVersion == _cfg.currentKeyVersion) return true;
    if (_cfg.allowPreviousKeyVersion && _cfg.currentKeyVersion > 1 &&
        keyVersion + 1 == _cfg.currentKeyVersion) {
        return true;
    }
    return false;
}

crypto_lib::aead::AeadKey KeyManager::deriveAeadKey(uint32_t readerId, uint32_t keyVersion) const {
    if (!isAcceptedKeyVersion(keyVersion)) {
        throw std::invalid_argument("KeyManager: key_version not accepted");
    }

    std::array<uint8_t, 8> salt{};
    putLe32(readerId, &salt[0]);
    putLe32(keyVersion, &salt[4]);

    constexpr std::string_view info = "access-aead-v1";

    crypto_lib::hkdf::Hkdf hkdf(
        std::span<const uint8_t>(_masterKey.data(), _masterKey.size()),
        std::span<const uint8_t>(salt.data(), salt.size()),
        info,
        /*outputLen=*/32);

    const auto okm = hkdf.derive();
    if (okm.size() != 32) {
        throw std::runtime_error("KeyManager: HKDF returned wrong length");
    }

    crypto_lib::aead::AeadKey out;
    std::copy(okm.begin(), okm.end(), out.key.begin());
    return out;
}

}  // namespace key_manager
