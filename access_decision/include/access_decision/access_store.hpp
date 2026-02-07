#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace access_decision {

class IAccessStore {
  public:
    virtual ~IAccessStore() = default;

    virtual std::optional<std::string> role_for_card_hmac(std::string_view card_hmac_hex) const = 0;

    virtual bool is_allowed(uint32_t door_id, std::string_view role) const = 0;
};

}  // namespace access_decision
