#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "packet.hpp"

namespace protocol::frame {

//! 16-byte authentication tag for Poly1305 MAC.
struct Tag16 {
    //! Raw tag bytes.
    std::array<uint8_t, 16> v{};
};

//! Complete encrypted frame containing header, ciphertext, and auth tag.
struct Frame {
    //! Plaintext header with metadata (not encrypted).
    packet::Header header{};
    //! Encrypted payload bytes.
    std::vector<uint8_t> ct{};
    //! Poly1305 authentication tag.
    Tag16 tag{};
};

//! Serializes a frame to bytes for transmission.
//! @param f [in] Frame to serialize.
//! @return Byte vector with magic, version, header, ciphertext length,
//! ciphertext, and tag.
std::vector<uint8_t> serialize(const Frame& f);

//! Parses raw bytes into a Frame structure.
//! @param bytes [in] Raw frame bytes to parse.
//! @param maxCtLen [in] Maximum allowed ciphertext length (prevents DoS).
//! @return Parsed frame structure.
//! @throws std::runtime_error on invalid magic, version, or malformed data.
Frame parseFrame(std::span<const uint8_t> bytes, uint32_t maxCtLen = 4096);

//! Size of the magic header identifier in bytes.
const uint8_t kMagicSize = 4;
//! Magic bytes identifying a valid frame: "AS01".
const uint8_t kMagic[kMagicSize] = {'A', 'S', '0', '1'};
//! Current protocol version number.
const uint8_t kVersion = 1;

}  // namespace protocol::frame
