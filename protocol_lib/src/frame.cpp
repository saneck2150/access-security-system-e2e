#include "protocol_lib/frame.hpp"
#include "protocol_lib/protocol_utils.hpp"

#include <cstring>
#include <stdexcept>

namespace protocol::frame {

std::vector<uint8_t> serialize(const Frame& f) {
    std::vector<uint8_t> out;
    out.reserve(4 + 1 + 48 + 4 + f.ct.size() + 16);

    out.insert(out.end(), kMagic, kMagic + 4);
    out.push_back(kVersion);

    protocol::utils::put_le32(f.header.reader_id, out);
    protocol::utils::put_le32(f.header.door_id, out);
    protocol::utils::put_le64(f.header.ts_unix_ms, out);
    protocol::utils::put_le64(f.header.seq, out);
    out.insert(out.end(), f.header.nonce.begin(), f.header.nonce.end());

    protocol::utils::put_le32(static_cast<uint32_t>(f.ct.size()), out);
    out.insert(out.end(), f.ct.begin(), f.ct.end());
    out.insert(out.end(), f.tag.v.begin(), f.tag.v.end());

    return out;
}

Frame parse(std::span<const uint8_t> bytes) {
    const size_t min_size = 4 + 1 + 48 + 4 + 16;
    if (bytes.size() < min_size)
        throw std::runtime_error("frame: too small");

    const uint8_t* p = bytes.data();
    if (std::memcmp(p, kMagic, 4) != 0)
        throw std::runtime_error("frame: bad magic");
    p += 4;

    const uint8_t ver = *p++;
    if (ver != kVersion)
        throw std::runtime_error("frame: bad version");

    Frame f;

    f.header.reader_id = protocol::utils::get_le32(p);
    p += 4;
    f.header.door_id = protocol::utils::get_le32(p);
    p += 4;
    f.header.ts_unix_ms = protocol::utils::get_le64(p);
    p += 8;
    f.header.seq = protocol::utils::get_le64(p);
    p += 8;

    std::memcpy(f.header.nonce.data(), p, f.header.nonce.size());
    p += f.header.nonce.size();

    const uint32_t ct_len = protocol::utils::get_le32(p);
    p += 4;

    const size_t remaining = (bytes.data() + bytes.size()) - p;
    if (remaining < (size_t)ct_len + 16)
        throw std::runtime_error("frame: length mismatch");

    f.ct.assign(p, p + ct_len);
    p += ct_len;

    std::memcpy(f.tag.v.data(), p, f.tag.v.size());
    return f;
}

}  // namespace protocol::frame
