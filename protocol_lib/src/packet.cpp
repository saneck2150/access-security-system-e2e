#include "protocol_lib/packet.hpp"

#include <cstdint>

#include "protocol_lib/protocol_utils.hpp"

namespace protocol::packet {

std::vector<uint8_t> Header::to_bytes() const {
    std::vector<uint8_t> out;
    out.reserve(4 + 4 + 8 + 8 + 4 +
                nonce.size());  // reader_id + door_id + ts + seq + key_version + nonce
    protocol::utils::put_le32(reader_id, out);
    protocol::utils::put_le32(door_id, out);
    protocol::utils::put_le64(ts_unix_ms, out);
    protocol::utils::put_le64(seq, out);

    protocol::utils::put_le32(key_version, out);

    out.insert(out.end(), nonce.begin(), nonce.end());
    return out;
}

}  // namespace protocol::packet
