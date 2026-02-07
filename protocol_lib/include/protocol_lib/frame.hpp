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
Frame parse(std::span<const uint8_t> bytes);

constexpr uint8_t kMagic[4] = {'A', 'S', '0', '1'};
constexpr uint8_t kVersion = 1;

}  // namespace protocol::frame
