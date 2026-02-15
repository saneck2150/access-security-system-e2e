#pragma once

#include "protocol_lib/frame.hpp"

#include <cstdint>
#include <span>

namespace protocol::frame {

class FrameParser {
  public:
    FrameParser(const std::span<const uint8_t>& bytes, uint32_t maxCtLen);

    Frame parse();

  private:
    // computed values
    struct ComputedValues {
        const size_t kVersionSize = sizeof(uint8_t);
        const size_t kU32 = sizeof(uint32_t);
        const size_t kU64 = sizeof(uint64_t);

        const size_t kHeaderFixedSize = (3 * kU32) + (2 * kU64);
        const size_t kNonceSize = std::tuple_size_v<decltype(Frame{}.header.nonce)>;
        const size_t kTagSize = std::tuple_size_v<decltype(Frame{}.tag.v)>;
        const size_t kCtLenSize = kU32;
        const size_t kMinFrameSize =
            kMagicSize + kVersionSize + kHeaderFixedSize + kNonceSize + kCtLenSize + kTagSize;
    };

    // input data
    std::span<const uint8_t> _bytes;
    uint32_t _maxCtLen;
    const uint8_t* _ptr;
    const uint8_t* _end;
    const ComputedValues _computedValues;

    // output
    Frame _frame;

    // helper functions
    void requireBytes(size_t n, const std::string& msg);
    void validateMinSize();
    void validateMagic();
    void validateVersion();
    void parseHeader();
    void parseCiphertext();
    void parseTag();
    void validateNoTrailingBytes();
};

} // namespace protocol::frame
