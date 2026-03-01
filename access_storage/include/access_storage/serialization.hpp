#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

//! Internal serialization utilities for audit log hashing.
namespace access_storage::detail {

//! Appends a 32-bit value in little-endian format to a buffer.
//! @param [in] v      Value to encode.
//! @param [out] out   Output buffer to append to.
void putLe32(uint32_t v, std::vector<uint8_t>& out);

//! Appends a 64-bit value in little-endian format to a buffer.
//! @param [in] v      Value to encode.
//! @param [out] out   Output buffer to append to.
void putLe64(uint64_t v, std::vector<uint8_t>& out);

//! Appends a length-prefixed string to a buffer.
//! Format: 4-byte LE length followed by raw bytes.
//! @param [in] s      String to encode.
//! @param [out] out   Output buffer to append to.
void putBytesWithLen(std::string_view s, std::vector<uint8_t>& out);

}  // namespace access_storage::detail
