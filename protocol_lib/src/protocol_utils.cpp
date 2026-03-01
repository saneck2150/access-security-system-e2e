#include "protocol_lib/protocol_utils.hpp"

namespace protocol::utils {

void put_le32(uint32_t v, std::vector<uint8_t>& out) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

void put_le64(uint64_t v, std::vector<uint8_t>& out) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
    }
}

uint32_t get_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t get_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

template <>
uint32_t read_le<uint32_t>(const uint8_t*& ptr) {
    uint32_t v = get_le32(ptr);
    ptr += sizeof(uint32_t);
    return v;
}

template <>
uint64_t read_le<uint64_t>(const uint8_t*& ptr) {
    uint64_t v = get_le64(ptr);
    ptr += sizeof(uint64_t);
    return v;
}

}  // namespace protocol::utils
