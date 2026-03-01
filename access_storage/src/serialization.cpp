#include "access_storage/serialization.hpp"

namespace access_storage::detail {

void putLe32(uint32_t v, std::vector<uint8_t>& out) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

void putLe64(uint64_t v, std::vector<uint8_t>& out) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
    }
}

void putBytesWithLen(std::string_view s, std::vector<uint8_t>& out) {
    putLe32(static_cast<uint32_t>(s.size()), out);
    out.insert(out.end(), s.begin(), s.end());
}

}  // namespace access_storage::detail
