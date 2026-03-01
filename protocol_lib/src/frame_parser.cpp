#include "protocol_lib/frame_parser.hpp"

#include <cstring>
#include <stdexcept>

#include "protocol_lib/protocol_utils.hpp"

namespace protocol::frame {

FrameParser::FrameParser(const std::span<const uint8_t>& bytes, uint32_t maxCtLen)
    : _bytes(bytes), _maxCtLen(maxCtLen), _ptr(bytes.data()), _end(bytes.data() + bytes.size()) {}

Frame FrameParser::parse() {
    validateMinSize();
    validateMagic();
    validateVersion();
    parseHeader();
    parseCiphertext();
    parseTag();
    validateNoTrailingBytes();
    return _frame;
}

void FrameParser::requireBytes(size_t n, const std::string& msg) {
    if (static_cast<size_t>(_end - _ptr) < n) {
        throw std::runtime_error(msg);
    }
}

void FrameParser::validateMinSize() {
    if (_bytes.size() < _computedValues.kMinFrameSize) {
        throw std::runtime_error("frame: too small");
    }
}

void FrameParser::validateMagic() {
    requireBytes(kMagicSize, "frame: too small");
    if (std::memcmp(_ptr, kMagic, kMagicSize) != 0) {
        throw std::runtime_error("frame: bad magic");
    }
    _ptr += kMagicSize;
}

void FrameParser::validateVersion() {
    requireBytes(_computedValues.kVersionSize, "frame: too small");
    const uint8_t ver = *_ptr++;
    if (ver != kVersion) {
        throw std::runtime_error("frame: bad version");
    }
}

void FrameParser::parseHeader() {
    requireBytes(
        _computedValues.kHeaderFixedSize + _computedValues.kNonceSize + _computedValues.kCtLenSize,
        "frame: too small");

    _frame.header.reader_id = protocol::utils::read_le<uint32_t>(_ptr);
    _frame.header.door_id = protocol::utils::read_le<uint32_t>(_ptr);
    _frame.header.ts_unix_ms = protocol::utils::read_le<uint64_t>(_ptr);
    _frame.header.seq = protocol::utils::read_le<uint64_t>(_ptr);
    _frame.header.key_version = protocol::utils::read_le<uint32_t>(_ptr);

    std::memcpy(_frame.header.nonce.data(), _ptr, _computedValues.kNonceSize);
    _ptr += _computedValues.kNonceSize;
}

void FrameParser::parseCiphertext() {
    const uint32_t ctLen = protocol::utils::read_le<uint32_t>(_ptr);

    if (ctLen > _maxCtLen) {
        throw std::runtime_error("frame: ctLen exceeds limit");
    }

    requireBytes(static_cast<size_t>(ctLen) + _computedValues.kTagSize, "frame: length mismatch");

    _frame.ct.assign(_ptr, _ptr + ctLen);
    _ptr += ctLen;
}

void FrameParser::parseTag() {
    std::memcpy(_frame.tag.v.data(), _ptr, _computedValues.kTagSize);
    _ptr += _computedValues.kTagSize;
}

void FrameParser::validateNoTrailingBytes() {
    if (_ptr != _end) {
        throw std::runtime_error("frame: trailing bytes");
    }
}

}  // namespace protocol::frame
