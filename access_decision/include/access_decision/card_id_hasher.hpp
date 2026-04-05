#pragma once

//! @file card_id_hasher.hpp
//! HMAC-based card ID hashing for privacy-preserving storage.

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace access_decision {

//! HMAC-SHA256 output size in bytes.
inline constexpr size_t kHmacOutputSize = 32;
//! Hex encoding alphabet.
inline constexpr const char* kHexChars = "0123456789abcdef";

//! Hashes card IDs using HMAC-SHA256 with a pepper key.
//! Provides privacy-preserving card storage (raw UIDs never stored).
class CardIdHasher {
  public:
    //! Constructs a hasher with the given pepper key.
    //! @param [in] pepperKey 32-byte HMAC key derived from master key.
    explicit CardIdHasher(std::array<uint8_t, kHmacOutputSize> pepperKey);

    //! Computes HMAC-SHA256 of a card ID and returns it as hex.
    //! @param [in] cardId The raw card UID string.
    //! @return 64-character lowercase hex string.
    std::string hmacHex(std::string_view cardId) const;

  private:
    //! HMAC pepper key derived from master key via HKDF.
    std::array<uint8_t, kHmacOutputSize> _pepper{};

    //! Converts raw bytes to lowercase hex string.
    //! @param [in] data   Pointer to byte array.
    //! @param [in] length Number of bytes to convert.
    //! @return Hex-encoded string (2 * length characters).
    std::string toHex(const uint8_t* data, size_t length) const;
};

}  // namespace access_decision
