#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "access_decision/access_store.hpp"

struct sqlite3;

//! SQLite-based persistent storage for access control data.
namespace access_storage {

//! Reader device information.
struct ReaderRow {
    //! Unique reader identifier.
    uint32_t reader_id = 0;
    //! Current encryption key version.
    uint32_t current_key_version = 0;
};

//! Reader-to-door binding.
struct ReaderDoorRow {
    //! Reader identifier.
    uint32_t reader_id = 0;
    //! Door identifier the reader controls.
    uint32_t door_id = 0;
};

//! Door-to-role permission mapping.
struct DoorRoleRow {
    //! Door identifier.
    uint32_t door_id = 0;
    //! Role name allowed to access this door.
    std::string role;
};

//! Card credential information.
struct CardRow {
    //! HMAC of card ID (hex-encoded).
    std::string card_hmac;
    //! Role assigned to this card.
    std::string role;
};

//! SQLite implementation of the access control store.
class SqliteAccessStore final : public access_decision::IAccessStore {
  public:
    //! Opens or creates a SQLite database at the given path.
    //! @param [in] path Path to SQLite database file.
    //! @throws std::runtime_error If database cannot be opened.
    explicit SqliteAccessStore(const std::string& path);

    ~SqliteAccessStore();

    SqliteAccessStore(const SqliteAccessStore&) = delete;
    SqliteAccessStore& operator=(const SqliteAccessStore&) = delete;

    //! Creates required tables if they don't exist.
    void initSchema();

    // === Card Management ===

    //! Inserts or updates a card with the given role.
    //! @param [in] cardHmacHex Hex-encoded HMAC of card ID.
    //! @param [in] role        Role to assign.
    void upsertCardHmac(std::string cardHmacHex, std::string role);

    //! Deletes a card by its HMAC.
    //! @param [in] card_hmac Hex-encoded HMAC to delete.
    void deleteCardHmac(std::string_view card_hmac);

    //! Lists cards with pagination.
    //! @param [in] limit  Maximum cards to return.
    //! @param [in] offset Number of cards to skip.
    //! @return Vector of card rows.
    std::vector<CardRow> listCards(size_t limit = 200, size_t offset = 0) const;

    //! Looks up the role for a card HMAC.
    //! @param [in] cardHmacHex Hex-encoded card HMAC.
    //! @return Role if found, nullopt otherwise.
    std::optional<std::string> roleForCardHmac(std::string_view cardHmacHex) const override;

    // === Door Role Management ===

    //! Allows a role to access a door.
    //! @param [in] doorId Door identifier.
    //! @param [in] role   Role name to allow.
    void allowRole(uint32_t doorId, std::string role);

    //! Revokes a role's access to a door.
    //! @param [in] door_id Door identifier.
    //! @param [in] role    Role name to revoke.
    void revokeRole(uint32_t door_id, std::string_view role);

    //! Lists door-role mappings.
    //! @param [in] door_id Filter by door (0 = all doors).
    //! @return Vector of door-role rows.
    std::vector<DoorRoleRow> listDoorRoles(uint32_t door_id = 0) const;

    //! Checks if a role is allowed for a door.
    //! @param [in] doorId Door identifier.
    //! @param [in] role   Role name to check.
    //! @return True if role is allowed.
    bool isAllowed(uint32_t doorId, std::string_view role) const override;

    // === Reader Management ===

    //! Inserts or updates a reader's key version.
    //! @param [in] reader_id           Reader identifier.
    //! @param [in] current_key_version Key version to set.
    void upsertReader(uint32_t reader_id, uint32_t current_key_version) override;

    //! Deletes a reader and its door bindings.
    //! @param [in] reader_id Reader to delete.
    void deleteReader(uint32_t reader_id);

    //! Lists all registered readers.
    //! @return Vector of reader rows.
    std::vector<ReaderRow> listReaders() const;

    //! Gets the current key version for a reader.
    //! @param [in] reader_id Reader identifier.
    //! @return Key version, or 0 if reader not found.
    uint32_t currentKeyVersionForReader(uint32_t reader_id) const override;

    // === Reader-Door Binding ===

    //! Binds a reader to a door.
    //! @param [in] reader_id Reader identifier.
    //! @param [in] door_id   Door identifier.
    void allowDoorForReader(uint32_t reader_id, uint32_t door_id) override;

    //! Unbinds a reader from a door.
    //! @param [in] reader_id Reader identifier.
    //! @param [in] door_id   Door identifier.
    void revokeDoorForReader(uint32_t reader_id, uint32_t door_id);

    //! Lists reader-door bindings.
    //! @param [in] reader_id Filter by reader (0 = all readers).
    //! @return Vector of reader-door rows.
    std::vector<ReaderDoorRow> listReaderDoors(uint32_t reader_id = 0) const;

    //! Checks if a reader is allowed to control a door.
    //! @param [in] reader_id Reader identifier.
    //! @param [in] door_id   Door identifier.
    //! @return True if binding exists.
    bool isReaderAllowedDoor(uint32_t reader_id, uint32_t door_id) const override;

    // === Direct Database Access ===

    //! Returns the raw SQLite handle for advanced operations.
    //! @return SQLite database handle.
    sqlite3* dbHandle() const { return _db; }

  private:
    //! SQLite database handle (owned).
    sqlite3* _db = nullptr;
};

}  // namespace access_storage
