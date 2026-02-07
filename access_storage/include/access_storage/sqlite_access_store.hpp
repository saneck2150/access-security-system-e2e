#pragma once
#include "access_decision/access_store.hpp"

#include <cstdint>
#include <optional>
#include <string>

struct sqlite3;

namespace access_storage {

class SqliteAccessStore final : public access_decision::IAccessStore {
  public:
    // path=":memory:" для тестов
    explicit SqliteAccessStore(const std::string& path);
    ~SqliteAccessStore();

    SqliteAccessStore(const SqliteAccessStore&) = delete;
    SqliteAccessStore& operator=(const SqliteAccessStore&) = delete;

    void init_schema();

    void upsert_card_hmac(std::string card_hmac_hex, std::string role);
    void allow_role(uint32_t door_id, std::string role);

    std::optional<std::string> role_for_card_hmac(std::string_view card_hmac_hex) const override;
    bool is_allowed(uint32_t door_id, std::string_view role) const override;

  private:
    sqlite3* _db = nullptr;
};

}  // namespace access_storage
