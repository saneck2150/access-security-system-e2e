#pragma once

#include <crypto_lib/secure_aead.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>
#include <protocol_lib/replay_window.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace access_core {

struct HandleResult {
    bool allow = false;
    std::string reason;
    std::vector<uint8_t> plaintext;
    protocol::packet::Header header;
};

HandleResult handle_frame(
    std::span<const uint8_t> frame_bytes, crypto_lib::aead::SecureAead& server_aead,
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replay_by_reader);

}  // namespace access_core
