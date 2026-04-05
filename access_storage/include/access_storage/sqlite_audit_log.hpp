#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

#include <access_decision/audit.hpp>

struct sqlite3;

//! Audit logging with cryptographic integrity.
namespace access_storage {

//! Size of HMAC-SHA256 hash in bytes.
inline constexpr size_t kHashSize = 32;

//! SQLite-backed audit log with HMAC chain for tamper detection.
class SqliteAuditLog final : public access_decision::IAuditLog {
  public:
    //! 32-byte hash type for HMAC operations.
    using Hash32 = std::array<uint8_t, kHashSize>;

    //! Constructs audit log with database and HMAC key.
    //! @param [in] db           SQLite database handle (non-owning).
    //! @param [in] hmacKey      32-byte key for HMAC chain.
    //! @param [in] chainEnabled If false, entries are stored without HMAC chaining.
    //! @throws std::invalid_argument If db is null.
    SqliteAuditLog(sqlite3* db, Hash32 hmacKey, bool chainEnabled = true);

    //! Appends an event to the audit log with chain hash.
    //! @param [in] e Event to log.
    //! @throws std::runtime_error If database operation fails.
    void append(access_decision::AuditEvent e) override;

  private:
    //! Database handle (non-owning).
    sqlite3* _db = nullptr;
    //! HMAC key for chain integrity.
    Hash32 _key{};
    //! If false, entries are logged without HMAC chaining.
    bool _chainEnabled = true;

    //! Creates audit_log and audit_anchor tables if not exist.
    void initSchema();

    //! Retrieves the hash of the last audit entry.
    //! @return Last entry hash, or zeros if no entries.
    Hash32 getLastEntryHash() const;

    //! Computes HMAC hash for an audit entry.
    //! @param [in] prevHash Previous entry's hash (for chaining).
    //! @param [in] e        Event data to hash.
    //! @return Computed entry hash.
    Hash32 computeEntryHash(const Hash32& prevHash, const access_decision::AuditEvent& e) const;

    //! Inserts event into audit_log table.
    //! @param [in] e          Event to insert.
    //! @param [in] prevHash   Previous entry hash.
    //! @param [in] entryHash  Computed hash for this entry.
    void insertAuditEntry(
        const access_decision::AuditEvent& e, const Hash32& prevHash, const Hash32& entryHash);

    //! Updates audit_anchor with the latest hash.
    //! @param [in] entryHash New last hash.
    //! @param [in] ts        Timestamp for anchor update.
    void updateAnchor(const Hash32& entryHash, uint64_t ts);
};

}  // namespace access_storage
