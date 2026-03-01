#pragma once

//! @file access_store.hpp
//! Abstract interface for access policy and card storage.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace access_decision {

//! Abstract interface for access policy storage.
//! Decouples DecisionEngine from storage backend (SQLite, in-memory, etc.).
//! Card IDs are stored as HMAC hashes for privacy.
class IAccessStore {
  public:
    virtual ~IAccessStore() = default;

    //! Looks up the role for a card by its HMAC hash.
    //! @param [in] cardHmacHex Hex-encoded HMAC-SHA256 of the card ID.
    //! @return The role string if found, std::nullopt otherwise.
    virtual std::optional<std::string> roleForCardHmac(std::string_view cardHmacHex) const = 0;

    //! Checks if a role is allowed to access a specific door.
    //! @param [in] doorId The door identifier.
    //! @param [in] role   The role to check.
    //! @return True if the role has permission for the door.
    virtual bool isAllowed(uint32_t doorId, std::string_view role) const = 0;

    //! Gets the current encryption key version for a reader.
    //! @param [in] reader_id The reader identifier.
    //! @return Current key version (0 if reader not found).
    virtual uint32_t currentKeyVersionForReader(uint32_t reader_id) const = 0;

    //! Registers or updates a reader with its current key version.
    //! @param [in] reader_id           The reader identifier.
    //! @param [in] current_key_version The key version the reader is using.
    virtual void upsertReader(uint32_t reader_id, uint32_t current_key_version) = 0;

    //! Checks if a reader is authorized to control a door.
    //! @param [in] reader_id The reader identifier.
    //! @param [in] door_id   The door identifier.
    //! @return True if the reader can control the door.
    virtual bool isReaderAllowedDoor(uint32_t reader_id, uint32_t door_id) const = 0;

    //! Grants a reader permission to control a door.
    //! @param [in] reader_id The reader identifier.
    //! @param [in] door_id   The door identifier.
    virtual void allowDoorForReader(uint32_t reader_id, uint32_t door_id) = 0;
};

}  // namespace access_decision
