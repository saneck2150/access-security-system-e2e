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
    virtual uint32_t currentKeyVersionForReader(uint32_t reader_id) const = 0;
    virtual void upsertReader(uint32_t reader_id, uint32_t current_key_version) = 0;
    virtual bool isReaderAllowedDoor(uint32_t reader_id, uint32_t door_id) const = 0;
    virtual void allowDoorForReader(uint32_t reader_id, uint32_t door_id) = 0;
};

} // namespace access_decision
