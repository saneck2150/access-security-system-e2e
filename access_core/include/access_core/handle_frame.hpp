#pragma once

#include "access_core/frame_decryptor.hpp"

#include <key_manager/key_manager.hpp>
#include <protocol_lib/frame.hpp>
#include <protocol_lib/packet.hpp>
#include <protocol_lib/replay_window.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace access_decision { class IAccessStore; }

namespace access_core {

struct FrameHandlerConfig {
    bool antiReplayEnabled = true;
    size_t replayWindowSize = 256;
    uint32_t maxCtLen = 4096;
    uint64_t maxSkewMs = 0;
    bool allowPreviousKeyVersion = true;
    bool enforceReaderDoorBinding = true;
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

    FrameHandler(const key_manager::KeyManager& keyManager,
                ReplayWindowMap& replayWindows,
                const access_decision::IAccessStore* store,
                FrameHandlerConfig config = {});

    HandleResult handle(std::span<const uint8_t> frameBytes);

  private:
    const key_manager::KeyManager& _keyManager;
    ReplayWindowMap& _replayWindows;
    const access_decision::IAccessStore* _store = nullptr;
    FrameHandlerConfig _config;

    HandleResult makeError(const std::string& reason,
                           const protocol::packet::Header& header = {}) const;

    protocol::replay::ReplayWindow* getOrCreateWindow(uint32_t readerId);
    bool isReplay(protocol::replay::ReplayWindow* window, uint64_t seq) const;
    HandleResult tryDecrypt(const protocol::frame::Frame& frame,
                        protocol::replay::ReplayWindow* window,
                        uint32_t currentKeyVersion);
};
} // namespace access_core
