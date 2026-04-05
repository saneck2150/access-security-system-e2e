#pragma once

#include <array>
#include <cstdint>
#include <string_view>

//! Hex string parsing utilities for key material loading.
namespace key_manager::hex {

//! Converts a single hex character to its 4-bit value.
//! @param [in] c Hex character ('0'-'9', 'a'-'f', 'A'-'F').
//! @return Value 0-15.
//! @throws std::invalid_argument if c is not a valid hex character.
uint8_t hexNibble(char c);

//! Parses a hex string into a fixed-size byte array.
//! @tparam N Size of output array in bytes.
//! @param [in] hex Hex string (whitespace is ignored, must contain 2*N hex chars).
//! @return Parsed byte array.
//! @throws std::invalid_argument if hex length is wrong or contains invalid chars.
template <size_t N>
std::array<uint8_t, N> parseHex(std::string_view hex);

}  // namespace key_manager::hex
