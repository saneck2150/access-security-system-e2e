#pragma once

#include <cstdint>
#include <span>

#include "protocol_lib/frame.hpp"

//! Stateful parser for deserializing raw byte buffers into Frame structures.
namespace protocol::frame {

//! Stateful parser for deserializing raw bytes into Frame structures.
class FrameParser {
  public:
    //! Constructs a parser for the given byte buffer.
    //! @param [in] bytes     Raw frame bytes to parse.
    //! @param [in] maxCtLen  Maximum allowed ciphertext length (DoS protection).
    FrameParser(const std::span<const uint8_t>& bytes, uint32_t maxCtLen);

    //! Parses the buffer and returns a Frame.
    //! @return Parsed frame structure.
    //! @throws std::runtime_error on invalid data.
    Frame parse();

  private:
    //! Pre-computed size constants derived from Frame structure.
    struct ComputedValues {
        //! Size of version field in bytes.
        const size_t kVersionSize = sizeof(uint8_t);
        //! Size of a 32-bit field in bytes.
        const size_t kU32 = sizeof(uint32_t);
        //! Size of a 64-bit field in bytes.
        const size_t kU64 = sizeof(uint64_t);

        //! Size of fixed header fields (reader_id, door_id, ts, seq, key_version).
        const size_t kHeaderFixedSize = (3 * kU32) + (2 * kU64);
        //! Size of cryptographic nonce in bytes.
        const size_t kNonceSize = std::tuple_size_v<decltype(Frame{}.header.nonce)>;
        //! Size of authentication tag in bytes.
        const size_t kTagSize = std::tuple_size_v<decltype(Frame{}.tag.v)>;
        //! Size of ciphertext length field in bytes.
        const size_t kCtLenSize = kU32;
        //! Minimum valid frame size (magic + version + header + nonce + ctLen +
        //! tag).
        const size_t kMinFrameSize =
            kMagicSize + kVersionSize + kHeaderFixedSize + kNonceSize + kCtLenSize + kTagSize;
    };

    //! Input byte span being parsed.
    std::span<const uint8_t> _bytes;
    //! Maximum allowed ciphertext length.
    uint32_t _maxCtLen;
    //! Current read position in the buffer.
    const uint8_t* _ptr;
    //! Pointer to end of buffer for bounds checking.
    const uint8_t* _end;
    //! Pre-computed size constants.
    const ComputedValues _computedValues;

    //! Output frame being constructed.
    Frame _frame;

    //! Ensures n bytes are available, throws with msg if not.
    //! @param [in] n   Number of bytes required.
    //! @param [in] msg Error message for exception.
    void requireBytes(size_t n, const std::string& msg);

    //! Validates minimum frame size.
    void validateMinSize();
    //! Validates and consumes magic bytes.
    void validateMagic();
    //! Validates and consumes version byte.
    void validateVersion();
    //! Parses header fields into _frame.header.
    void parseHeader();
    //! Parses ciphertext into _frame.ct.
    void parseCiphertext();
    //! Parses authentication tag into _frame.tag.
    void parseTag();
    //! Ensures no trailing bytes remain after parsing.
    void validateNoTrailingBytes();
};

}  // namespace protocol::frame
