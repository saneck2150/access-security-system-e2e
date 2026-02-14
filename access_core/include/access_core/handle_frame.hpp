#pragma once

#include "access_core/frame_decryptor.hpp"

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

struct FrameHandlerConfig {
    bool antiReplayEnabled = true;
    size_t replayWindowSize = 256;
    uint32_t maxCtLen = 4096;
    uint64_t maxSkewMs = 0;
};

struct HandleResult {
    bool allow = false;
    std::string reason;
    std::vector<uint8_t> plaintext;
    protocol::packet::Header header;
};

class FrameHandler {
  public:
    using ReplayWindowMap = std::unordered_map<uint32_t, protocol::replay::ReplayWindow>;

    FrameHandler(crypto_lib::aead::SecureAead& aead, ReplayWindowMap& replayWindows,
                 FrameHandlerConfig config = {});

    HandleResult handle(std::span<const uint8_t> frameBytes);

  private:
    FrameDecryptor _decryptor;
    ReplayWindowMap& _replayWindows;
    FrameHandlerConfig _config;

    HandleResult makeError(const std::string& reason,
                           const protocol::packet::Header& header = {}) const;
    protocol::replay::ReplayWindow* getOrCreateWindow(uint32_t readerId);
    bool isReplay(protocol::replay::ReplayWindow* window, uint64_t seq) const;
    HandleResult processDecryption(const protocol::frame::Frame& frame,
                                   protocol::replay::ReplayWindow* window);
};

} // namespace access_core
