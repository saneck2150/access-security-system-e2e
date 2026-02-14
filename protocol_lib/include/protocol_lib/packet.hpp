#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace protocol::packet {

struct Header {
    uint32_t reader_id{};
    uint32_t door_id{};
    uint64_t ts_unix_ms{};
    uint64_t seq{};

    std::array<uint8_t, 24> nonce{};

    std::vector<uint8_t> to_bytes() const;
};

} // namespace protocol::packet