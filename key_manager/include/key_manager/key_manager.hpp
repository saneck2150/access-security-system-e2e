#pragma once

#include <crypto_lib/hkdf.hpp>
#include <crypto_lib/secure_aead.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace key_manager {

struct KeyManagerConfig {
    uint32_t currentKeyVersion = 1;
    bool allowPreviousKeyVersion = true;  
};

class KeyManager {
  public:
    using MasterKey = std::array<uint8_t, 32>;

    KeyManager(MasterKey masterKey, KeyManagerConfig cfg = {});

    static MasterKey loadMasterKeyHexFile(const std::string& path);

    bool isAcceptedKeyVersion(uint32_t keyVersion) const;

    crypto_lib::aead::AeadKey deriveAeadKey(uint32_t readerId, uint32_t keyVersion) const;

  private:
    MasterKey _masterKey{};
    KeyManagerConfig _cfg{};

    void putLe32(uint32_t v, uint8_t out[4]) const;
};

}  // namespace key_manager
