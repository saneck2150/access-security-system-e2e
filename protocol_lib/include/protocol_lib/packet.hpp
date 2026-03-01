#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace protocol::packet {

//! Protocol header containing metadata for encrypted frames.
struct Header {
    //! Identifier of the reader device that sent the frame.
    uint32_t reader_id{};
    //! Identifier of the door associated with this access attempt.
    uint32_t door_id{};
    //! Unix timestamp in milliseconds when the frame was created.
    uint64_t ts_unix_ms{};
    //! Sequence number for replay attack detection.
    uint64_t seq{};

    //! Version of the encryption key used for this frame.
    uint32_t key_version{};

    //! Cryptographic nonce for XChaCha20-Poly1305 (24 bytes).
    std::array<uint8_t, 24> nonce{};

    //! Serializes the header to a byte vector for transmission.
    //! @return Serialized header bytes in little-endian format.
    std::vector<uint8_t> to_bytes() const;
};

}  // namespace protocol::packet
