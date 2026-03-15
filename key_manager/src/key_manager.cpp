#include <fstream>
#include <stdexcept>
#include <string>

#include <key_manager/hex_utils.hpp>
#include <key_manager/key_manager.hpp>

namespace key_manager {

namespace {

//! HKDF info string for AEAD key derivation.
constexpr std::string_view kAeadKeyInfo = "access-aead-v1";

//! HKDF info string for card pepper derivation.
constexpr std::string_view kCardPepperInfo = "card-pepper-v1";

//! HKDF salt string for audit HMAC key derivation.
constexpr std::string_view kAuditHmacSalt = "audit-chain-salt-v1";

//! HKDF info string for audit HMAC key derivation.
constexpr std::string_view kAuditHmacInfo = "audit-hmac-v1";

//! Size of AEAD salt (reader_id + key_version).
constexpr size_t kAeadSaltSize = sizeof(uint32_t) * 2;

//! Size of card pepper salt (key_version only).
constexpr size_t kCardPepperSaltSize = sizeof(uint32_t);

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

KeyManager::MasterKey loadMasterKeyHexFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("loadMasterKeyHexFile: failed to open file: " + path);
    }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return hex::parseHex<kMasterKeySize>(content);
}

bool KeyManager::isAcceptedKeyVersion(uint32_t keyVersion) const {
    if (keyVersion == 0) {
        return false;
    }
    if (keyVersion == _cfg.currentKeyVersion) {
        return true;
    }
    if (_cfg.allowPreviousKeyVersion && _cfg.currentKeyVersion > 1 &&
        keyVersion + 1 == _cfg.currentKeyVersion) {
        return true;
    }
    return false;
}

crypto_lib::aead::AeadKey KeyManager::deriveAeadKey(uint32_t readerId, uint32_t keyVersion) const {
    // Key version validation is handled by FrameHandler via the store
    // deriveAeadKey only derives keys; policy is enforced elsewhere

    std::array<uint8_t, kAeadSaltSize> salt{};
    putLe32(readerId, &salt[0]);
    putLe32(keyVersion, &salt[sizeof(uint32_t)]);

    crypto_lib::hkdf::Hkdf hkdf(std::span<const uint8_t>(_masterKey.data(), _masterKey.size()),
        std::span<const uint8_t>(salt.data(), salt.size()),
        kAeadKeyInfo,
        kAeadKeySize);

    const auto okm = hkdf.derive();
    if (okm.size() != kAeadKeySize) {
        throw std::runtime_error("KeyManager: HKDF returned wrong length");
    }

    crypto_lib::aead::AeadKey out;
    std::copy(okm.begin(), okm.end(), out.key.begin());
    return out;
}

std::array<uint8_t, kCardPepperSize> KeyManager::deriveCardPepper(uint32_t keyVersion) const {
    if (keyVersion == 0) {
        throw std::invalid_argument("KeyManager: keyVersion must be > 0");
    }

    std::array<uint8_t, kCardPepperSaltSize> salt{};
    putLe32(keyVersion, salt.data());

    crypto_lib::hkdf::Hkdf hkdf(std::span<const uint8_t>(_masterKey.data(), _masterKey.size()),
        std::span<const uint8_t>(salt.data(), salt.size()),
        kCardPepperInfo,
        kCardPepperSize);

    const auto okm = hkdf.derive();
    if (okm.size() != kCardPepperSize) {
        throw std::runtime_error("KeyManager: HKDF wrong length");
    }

    std::array<uint8_t, kCardPepperSize> out{};
    std::copy(okm.begin(), okm.end(), out.begin());
    return out;
}

crypto_lib::aead::AeadKey KeyManager::masterAsAeadKey() const {
    crypto_lib::aead::AeadKey out;
    std::copy(_masterKey.begin(), _masterKey.end(), out.key.begin());
    return out;
}

std::array<uint8_t, kAuditHmacKeySize> KeyManager::deriveAuditHmacKey() const {
    const auto salt = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(kAuditHmacSalt.data()), kAuditHmacSalt.size());

    crypto_lib::hkdf::Hkdf hkdf(std::span<const uint8_t>(_masterKey.data(), _masterKey.size()),
        salt,
        kAuditHmacInfo,
        kAuditHmacKeySize);

    const auto okm = hkdf.derive();
    if (okm.size() != kAuditHmacKeySize) {
        throw std::runtime_error("KeyManager: HKDF returned wrong length (audit key)");
    }

    std::array<uint8_t, kAuditHmacKeySize> out{};
    std::copy(okm.begin(), okm.end(), out.begin());
    return out;
}

}  // namespace key_manager
