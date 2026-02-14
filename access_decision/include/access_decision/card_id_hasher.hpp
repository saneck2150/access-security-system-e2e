#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace access_decision {

constexpr uint8_t outputSize = 32;
constexpr const char* kHexChars = "0123456789abcdef";
class CardIdHasher {
  public:
    explicit CardIdHasher(std::array<uint8_t, outputSize> pepperKey);

    std::string hmacHex(std::string_view cardId) const;

  private:
    std::array<uint8_t, outputSize> _pepper{};

    std::string toHex(const uint8_t* data, size_t length) const;
};

} // namespace access_decision
