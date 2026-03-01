#include <cctype>
#include <stdexcept>
#include <string>

#include <key_manager/hex_utils.hpp>
#include <key_manager/key_manager.hpp>

namespace key_manager::hex {

uint8_t hexNibble(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + (c - 'a'));
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(10 + (c - 'A'));
    }
    throw std::invalid_argument("hex_utils: invalid hex character");
}

template <>
std::array<uint8_t, kMasterKeySize> parseHex<kMasterKeySize>(std::string_view s) {
    std::string hex;
    hex.reserve(s.size());
    for (char ch : s) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            hex.push_back(ch);
        }
    }

    if (hex.size() != kMasterKeyHexChars) {
        throw std::invalid_argument("hex_utils: expected " + std::to_string(kMasterKeyHexChars) +
                                    " hex chars, got " + std::to_string(hex.size()));
    }

    std::array<uint8_t, kMasterKeySize> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        const uint8_t hi = hexNibble(hex[2 * i]);
        const uint8_t lo = hexNibble(hex[2 * i + 1]);
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

}  // namespace key_manager::hex
