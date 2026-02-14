#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace access_decision {

class IAccessStore {
  public:
    virtual ~IAccessStore() = default;

    virtual std::optional<std::string> roleForCardHmac(std::string_view cardHmacHex) const = 0;

    virtual bool isAllowed(uint32_t doorId, std::string_view role) const = 0;
};

} // namespace access_decision
