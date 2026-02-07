#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace access_decision {

// HMAC-SHA-256(card_id) -> hex string (64 chars)
class CardIdHasher {
  public:
    explicit CardIdHasher(std::array<uint8_t, 32> pepper_key);

    std::string hmac_hex(std::string_view card_id) const;

  private:
    std::array<uint8_t, 32> _pepper{};
};

}  // namespace access_decision
