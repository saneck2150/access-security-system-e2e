#include <access_storage/audit_verify.hpp>

#include <crypto_lib/crypto_utils.hpp>

#include <sqlite3.h>
#include <sodium.h>

#include <cstring>
#include <string_view>
#include <vector>

namespace access_storage {

static void putLe32(uint32_t v, std::vector<uint8_t>& out) {
    out.push_back(static_cast<uint8_t>( v        & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8 ) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

static void putLe64(uint64_t v, std::vector<uint8_t>& out) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (8*i)) & 0xff));
}

static void putBytesWithLen(std::string_view s, std::vector<uint8_t>& out) {
    putLe32(static_cast<uint32_t>(s.size()), out);
    out.insert(out.end(), s.begin(), s.end());
}

///@todo split and move to _utils cpp/hpp
static std::array<uint8_t,32> computeEntryHash(const std::array<uint8_t,32>& key,
                                               const std::array<uint8_t,32>& prev,
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
    data.reserve(32 + fields.size());
    data.insert(data.end(), prev.begin(), prev.end());
    data.insert(data.end(), fields.begin(), fields.end());

    unsigned char out[32]{};
    crypto_lib::utils::hmac_sha256(
        std::span<const uint8_t>(key.data(), key.size()),
        std::span<const uint8_t>(data.data(), data.size()),
        out);

    std::array<uint8_t,32> h{};
    std::memcpy(h.data(), out, 32);
    return h;
}

///@todo split and move to _utils cpp/hpp
AuditVerifyResult verifyAuditChain(sqlite3* db, const std::array<uint8_t,32>& hmacKey) {
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

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        res.ok = false;
        res.error = "prepare failed";
        return res;
    }

    std::array<uint8_t,32> expectedPrev{};
    expectedPrev.fill(0);

    while (true) {
        const int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(st);
            res.ok = false;
            res.error = "step failed";
            return res;
        }

        const int64_t id = sqlite3_column_int64(st, 0);
        const uint64_t ts = static_cast<uint64_t>(sqlite3_column_int64(st, 1));
        const uint32_t reader_id = static_cast<uint32_t>(sqlite3_column_int(st, 2));
        const uint32_t door_id   = static_cast<uint32_t>(sqlite3_column_int(st, 3));
        const uint64_t seq       = static_cast<uint64_t>(sqlite3_column_int64(st, 4));
        const bool allow         = sqlite3_column_int(st, 5) != 0;

        const char* reason = reinterpret_cast<const char*>(sqlite3_column_text(st, 6));
        const char* card_hmac = reinterpret_cast<const char*>(sqlite3_column_text(st, 7));
        const char* action = reinterpret_cast<const char*>(sqlite3_column_text(st, 8));

        const void* prevBlob = sqlite3_column_blob(st, 9);
        const int prevN = sqlite3_column_bytes(st, 9);
        const void* entryBlob = sqlite3_column_blob(st, 10);
        const int entryN = sqlite3_column_bytes(st, 10);

        if (!prevBlob || prevN != 32 || !entryBlob || entryN != 32) {
            sqlite3_finalize(st);
            res.ok = false;
            res.bad_id = id;
            res.error = "bad hash blob length";
            return res;
        }

        std::array<uint8_t,32> storedPrev{};
        std::array<uint8_t,32> storedEntry{};
        std::memcpy(storedPrev.data(), prevBlob, 32);
        std::memcpy(storedEntry.data(), entryBlob, 32);

        if (sodium_memcmp(storedPrev.data(), expectedPrev.data(), 32) != 0) {
            sqlite3_finalize(st);
            res.ok = false;
            res.bad_id = id;
            res.error = "prev_hash mismatch";
            return res;
        }

        const auto expectedEntry = computeEntryHash(
            hmacKey, expectedPrev,
            ts, reader_id, door_id, seq, allow,
            reason ? std::string_view(reason) : std::string_view(),
            card_hmac ? std::string_view(card_hmac) : std::string_view(),
            action ? std::string_view(action) : std::string_view());

        if (sodium_memcmp(storedEntry.data(), expectedEntry.data(), 32) != 0) {
            sqlite3_finalize(st);
            res.ok = false;
            res.bad_id = id;
            res.error = "entry_hash mismatch";
            return res;
        }

        expectedPrev = storedEntry;
    }

    sqlite3_finalize(st);
    res.ok = true;
    res.error = "";
    return res;
}

} // namespace access_storage
