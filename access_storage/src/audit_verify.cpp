#include <cstring>
#include <string_view>
#include <vector>

#include <access_storage/audit_verify.hpp>
#include <access_storage/serialization.hpp>
#include <access_storage/sqlite_helpers.hpp>
#include <crypto_lib/crypto_utils.hpp>
#include <sodium.h>
#include <sqlite3.h>

namespace access_storage {

using Hash32 = std::array<uint8_t, kVerifyHashSize>;
using detail::prepareOrThrow;
using detail::putBytesWithLen;
using detail::putLe32;
using detail::putLe64;
using detail::StmtGuard;

namespace {

Hash32 computeEntryHash(const Hash32& key,
    const Hash32& prev,
    uint64_t ts,
    uint32_t reader_id,
    uint32_t door_id,
    uint64_t seq,
    bool allow,
    std::string_view reason,
    std::string_view card_hmac,
    std::string_view action) {
    std::vector<uint8_t> fields;
    fields.reserve(64 + reason.size() + card_hmac.size() + action.size());

    putLe64(ts, fields);
    putLe32(reader_id, fields);
    putLe32(door_id, fields);
    putLe64(seq, fields);
    fields.push_back(static_cast<uint8_t>(allow ? 1 : 0));
    putBytesWithLen(reason, fields);
    putBytesWithLen(card_hmac, fields);
    putBytesWithLen(action, fields);

    std::vector<uint8_t> data;
    data.reserve(kVerifyHashSize + fields.size());
    data.insert(data.end(), prev.begin(), prev.end());
    data.insert(data.end(), fields.begin(), fields.end());

    unsigned char out[kVerifyHashSize]{};
    crypto_lib::utils::hmac_sha256(std::span<const uint8_t>(key.data(), key.size()),
        std::span<const uint8_t>(data.data(), data.size()),
        out);

    Hash32 h{};
    std::memcpy(h.data(), out, kVerifyHashSize);
    return h;
}

struct AuditRow {
    int64_t id = 0;
    uint64_t ts = 0;
    uint32_t reader_id = 0;
    uint32_t door_id = 0;
    uint64_t seq = 0;
    bool allow = false;
    std::string_view reason;
    std::string_view card_hmac;
    std::string_view action;
    Hash32 storedPrev{};
    Hash32 storedEntry{};
};

bool extractRow(sqlite3_stmt* st, AuditRow& row) {
    row.id = sqlite3_column_int64(st, 0);
    row.ts = static_cast<uint64_t>(sqlite3_column_int64(st, 1));
    row.reader_id = static_cast<uint32_t>(sqlite3_column_int(st, 2));
    row.door_id = static_cast<uint32_t>(sqlite3_column_int(st, 3));
    row.seq = static_cast<uint64_t>(sqlite3_column_int64(st, 4));
    row.allow = sqlite3_column_int(st, 5) != 0;

    const char* reason = reinterpret_cast<const char*>(sqlite3_column_text(st, 6));
    const char* card_hmac = reinterpret_cast<const char*>(sqlite3_column_text(st, 7));
    const char* action = reinterpret_cast<const char*>(sqlite3_column_text(st, 8));

    row.reason = reason ? std::string_view(reason) : std::string_view();
    row.card_hmac = card_hmac ? std::string_view(card_hmac) : std::string_view();
    row.action = action ? std::string_view(action) : std::string_view();

    const void* prevBlob = sqlite3_column_blob(st, 9);
    const int prevN = sqlite3_column_bytes(st, 9);
    const void* entryBlob = sqlite3_column_blob(st, 10);
    const int entryN = sqlite3_column_bytes(st, 10);

    if (!prevBlob || prevN != static_cast<int>(kVerifyHashSize) || !entryBlob ||
        entryN != static_cast<int>(kVerifyHashSize)) {
        return false;
    }

    std::memcpy(row.storedPrev.data(), prevBlob, kVerifyHashSize);
    std::memcpy(row.storedEntry.data(), entryBlob, kVerifyHashSize);
    return true;
}

AuditVerifyResult verifyRow(
    const Hash32& hmacKey, const AuditRow& row, const Hash32& expectedPrev) {
    AuditVerifyResult res;

    if (sodium_memcmp(row.storedPrev.data(), expectedPrev.data(), kVerifyHashSize) != 0) {
        res.ok = false;
        res.bad_id = row.id;
        res.error = "prev_hash mismatch";
        return res;
    }

    const auto expectedEntry = computeEntryHash(hmacKey,
        expectedPrev,
        row.ts,
        row.reader_id,
        row.door_id,
        row.seq,
        row.allow,
        row.reason,
        row.card_hmac,
        row.action);

    if (sodium_memcmp(row.storedEntry.data(), expectedEntry.data(), kVerifyHashSize) != 0) {
        res.ok = false;
        res.bad_id = row.id;
        res.error = "entry_hash mismatch";
        return res;
    }

    res.ok = true;
    return res;
}

AuditVerifyResult verifyAnchor(sqlite3* db, const Hash32& lastEntry, bool anyRows) {
    AuditVerifyResult res;

    const char* sql = "SELECT last_hash FROM audit_anchor WHERE id = 1;";
    StmtGuard guard(prepareOrThrow(db, sql));

    const int rc = sqlite3_step(guard.get());
    if (rc != SQLITE_ROW) {
        res.ok = false;
        res.error = "anchor row missing";
        return res;
    }

    const void* blob = sqlite3_column_blob(guard.get(), 0);
    const int n = sqlite3_column_bytes(guard.get(), 0);
    if (!blob || n != static_cast<int>(kVerifyHashSize)) {
        res.ok = false;
        res.error = "anchor last_hash bad blob";
        return res;
    }

    Hash32 anchor{};
    std::memcpy(anchor.data(), blob, kVerifyHashSize);

    if (sodium_memcmp(anchor.data(), lastEntry.data(), kVerifyHashSize) != 0) {
        res.ok = false;
        res.bad_id = anyRows ? -2 : -1;
        res.error = "anchor mismatch (possible truncation)";
        return res;
    }

    res.ok = true;
    return res;
}

}  // namespace

AuditVerifyResult verifyAuditChain(sqlite3* db, const Hash32& hmacKey) {
    AuditVerifyResult res;

    if (!db) {
        res.ok = false;
        res.error = "db is null";
        return res;
    }

    const char* sql =
        "SELECT id, ts_unix_ms, reader_id, door_id, seq, allow, reason, "
        "       COALESCE(card_hmac,''), COALESCE(action,''), prev_hash, entry_hash "
        "FROM audit_log ORDER BY id ASC;";

    StmtGuard guard(prepareOrThrow(db, sql));

    Hash32 expectedPrev{};
    expectedPrev.fill(0);
    Hash32 lastEntry{};
    lastEntry.fill(0);
    bool anyRows = false;

    while (true) {
        const int rc = sqlite3_step(guard.get());
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            res.ok = false;
            res.error = "step failed";
            return res;
        }

        AuditRow row;
        if (!extractRow(guard.get(), row)) {
            res.ok = false;
            res.bad_id = row.id;
            res.error = "bad hash blob length";
            return res;
        }

        auto rowResult = verifyRow(hmacKey, row, expectedPrev);
        if (!rowResult.ok) {
            return rowResult;
        }

        anyRows = true;
        lastEntry = row.storedEntry;
        expectedPrev = row.storedEntry;
    }

    return verifyAnchor(db, lastEntry, anyRows);
}

}  // namespace access_storage
