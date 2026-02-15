#pragma once

#include "access_decision/access_store.hpp"

#include <cstdint>
#include <optional>
#include <string>

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

  private:
    sqlite3* _db = nullptr;
};

} // namespace access_storage
