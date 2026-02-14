#pragma once
#include "packet.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace protocol::frame {

struct Tag16 {
    std::array<uint8_t, 16> v{};
};

struct Frame {
    packet::Header header{};
    std::vector<uint8_t> ct{};
    Tag16 tag{};
};
std::vector<uint8_t> serialize(const Frame& f);

Frame parseFrame(std::span<const uint8_t> bytes, uint32_t maxCtLen = 4096);

const uint8_t kMagicSize = 4;
const uint8_t kMagic[kMagicSize] = {'A', 'S', '0', '1'};
const uint8_t kVersion = 1;

} // namespace protocol::frame
