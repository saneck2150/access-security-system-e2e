#include "protocol_lib/frame.hpp"
#include "protocol_lib/frame_parser.hpp"
#include "protocol_lib/protocol_utils.hpp"

#include <cstring>
#include <stdexcept>

namespace protocol::frame {

std::vector<uint8_t> serialize(const Frame& frame) {
    std::vector<uint8_t> out;
    out.reserve(4 + 1 + 52 + 4 + frame.ct.size() + 16);

    out.insert(out.end(), kMagic, kMagic + 4);
    out.push_back(kVersion);

    protocol::utils::put_le32(frame.header.reader_id, out);
    protocol::utils::put_le32(frame.header.door_id, out);
    protocol::utils::put_le64(frame.header.ts_unix_ms, out);
    protocol::utils::put_le64(frame.header.seq, out);

    protocol::utils::put_le32(frame.header.key_version, out);

    out.insert(out.end(), frame.header.nonce.begin(), frame.header.nonce.end());

    protocol::utils::put_le32(static_cast<uint32_t>(frame.ct.size()), out);
    out.insert(out.end(), frame.ct.begin(), frame.ct.end());
    out.insert(out.end(), frame.tag.v.begin(), frame.tag.v.end());

    return out;
}

Frame parseFrame(std::span<const uint8_t> bytes, uint32_t maxCtLen) {
    FrameParser parser(bytes, maxCtLen);
    return parser.parse();
}

} // namespace protocol::frame
