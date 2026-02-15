#pragma once

#include <array>
#include <cstdint>
#include <string>

struct sqlite3;

namespace access_storage {

struct AuditVerifyResult {
    bool ok = false;
    int64_t bad_id = -1;      // row id where failed
    std::string error;        // message
};

AuditVerifyResult verifyAuditChain(sqlite3* db, const std::array<uint8_t,32>& hmacKey);

} // namespace access_storage
