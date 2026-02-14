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

  private:
    sqlite3* _db = nullptr;
};

} // namespace access_storage
