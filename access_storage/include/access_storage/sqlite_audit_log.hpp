#pragma once

#include <access_decision/audit.hpp>

#include <array>
#include <cstdint>

struct sqlite3;

namespace access_storage {

class SqliteAuditLog final : public access_decision::IAuditLog {
  public:
    using Hash32 = std::array<uint8_t, 32>;

    SqliteAuditLog(sqlite3* db, Hash32 hmacKey);

    void append(access_decision::AuditEvent e) override;

  private:
    sqlite3* _db = nullptr; // non-owning
    Hash32 _key{};

    void initSchema();
    Hash32 getLastEntryHash() const;
///@todo static?
    static void putLe32(uint32_t v, std::vector<uint8_t>& out);
    static void putLe64(uint64_t v, std::vector<uint8_t>& out);
    static void putBytesWithLen(std::string_view s, std::vector<uint8_t>& out);

    Hash32 computeEntryHash(const Hash32& prevHash,
                            const access_decision::AuditEvent& e) const;
};

} // namespace access_storage
