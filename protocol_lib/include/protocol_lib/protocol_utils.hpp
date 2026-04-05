#pragma once

#include <cstdint>
#include <vector>

//! Little-endian serialization and deserialization helpers for protocol frames.
namespace protocol::utils {

//! Appends a 32-bit value to a byte vector in little-endian order.
//! @param [in]  v   Value to append.
//! @param [out] out Target vector to append bytes to.
void put_le32(uint32_t v, std::vector<uint8_t>& out);

//! Appends a 64-bit value to a byte vector in little-endian order.
//! @param [in]  v   Value to append.
//! @param [out] out Target vector to append bytes to.
void put_le64(uint64_t v, std::vector<uint8_t>& out);

//! Reads a 32-bit value from memory in little-endian order.
//! @param [in] p Pointer to at least 4 bytes of data.
//! @return Decoded 32-bit value.
uint32_t get_le32(const uint8_t* p);

//! Reads a 64-bit value from memory in little-endian order.
//! @param [in] p Pointer to at least 8 bytes of data.
//! @return Decoded 64-bit value.
uint64_t get_le64(const uint8_t* p);

//! Reads a little-endian value from a pointer and advances the pointer.
//! @tparam T Integer type to read (uint32_t or uint64_t).
//! @param [in,out] ptr Pointer to data; advanced by sizeof(T) after read.
//! @return Decoded value of type T.
template <typename T>
T read_le(const uint8_t*& ptr);

}  // namespace protocol::utils
