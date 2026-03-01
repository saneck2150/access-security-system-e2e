#pragma once

//! @file http_utils.hpp
//! HTTP utilities for the admin server.

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <sqlite3.h>

namespace admin {

using json = nlohmann::json;

//! Hex character lookup table.
constexpr const char* kHexChars = "0123456789abcdef";

//! SQL for integrity check.
constexpr const char* kIntegrityCheckSql = "PRAGMA integrity_check;";

//! Returns current Unix time in milliseconds.
//! @return Milliseconds since Unix epoch.
uint64_t nowUnixMs();

//! Initializes libsodium or throws on failure.
void sodiumInitOrThrow();

//! Sets JSON response with status code.
//! @param [out] res    HTTP response to modify.
//! @param [in]  j      JSON object to send.
//! @param [in]  status HTTP status code (default 200).
void setJson(httplib::Response& res, const json& j, int status = 200);

//! Checks X-Admin-Token header against expected token.
//! @param [in] req   HTTP request to check.
//! @param [in] token Expected token (empty = no auth required).
//! @return True if authorized.
bool checkAuth(const httplib::Request& req, const std::string& token);

//! Converts a hex character to nibble value.
//! @param [in] c Hex character (0-9, a-f, A-F).
//! @return Nibble value (0-15).
uint8_t hexNibble(char c);

//! Converts hex string to byte vector.
//! @param [in] hex Hex string (whitespace ignored).
//! @return Decoded bytes.
std::vector<uint8_t> hexToBytes(std::string_view hex);

//! Converts byte vector to lowercase hex string.
//! @param [in] v Bytes to convert.
//! @return Hex string.
std::string bytesToHex(const std::vector<uint8_t>& v);

//! Checks SQLite database integrity.
//! @param [in]  path Database file path.
//! @param [out] err  Error message if failed.
//! @return True if integrity check passed.
bool sqliteIntegrityOk(const std::string& path, std::string& err);

}  // namespace admin
