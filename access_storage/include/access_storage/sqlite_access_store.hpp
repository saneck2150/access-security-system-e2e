#pragma once

#include "access_decision/access_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace access_storage {

class SqliteAccessStore final : public access_decision::IAccessStore {
  public:
    explicit SqliteAccessStore(const std::string& path);
    ~SqliteAccessStore();

    SqliteAccessStore(const SqliteAccessStore&) = delete;
    SqliteAccessStore& operator=(const SqliteAccessStore&) = delete;

    void initSchema();

    void upsertCardHmac(std::string cardHmacHex, std::string role);
    void allowRole(uint32_t doorId, std::string role);

    std::optional<std::string> roleForCardHmac(std::string_view cardHmacHex) const override;
    bool isAllowed(uint32_t doorId, std::string_view role) const override;
    uint32_t currentKeyVersionForReader(uint32_t reader_id) const override;
    void upsertReader(uint32_t reader_id, uint32_t current_key_version) override;
    bool isReaderAllowedDoor(uint32_t reader_id, uint32_t door_id) const override;
    void allowDoorForReader(uint32_t reader_id, uint32_t door_id) override;
    sqlite3* dbHandle() const { return _db; }

    
    /// @todo buss methods, move somewhere else
    struct ReaderRow {
        uint32_t reader_id = 0;
        uint32_t current_key_version = 0;
    };
    struct ReaderDoorRow {
        uint32_t reader_id = 0;
        uint32_t door_id = 0;
    };
    struct DoorRoleRow {
        uint32_t door_id = 0;
        std::string role;
    };
    struct CardRow {
        std::string card_hmac;
        std::string role;
    };

    std::vector<ReaderRow> listReaders() const;
    std::vector<ReaderDoorRow> listReaderDoors(uint32_t reader_id = 0) const;
    std::vector<DoorRoleRow> listDoorRoles(uint32_t door_id = 0) const;
    std::vector<CardRow> listCards(size_t limit = 200, size_t offset = 0) const;

    void deleteReader(uint32_t reader_id);
    void revokeDoorForReader(uint32_t reader_id, uint32_t door_id);
    void revokeRole(uint32_t door_id, std::string_view role);
    void deleteCardHmac(std::string_view card_hmac);

  private:
    sqlite3* _db = nullptr;
};

} // namespace access_storage
