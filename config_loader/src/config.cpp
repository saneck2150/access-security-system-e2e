#include <config_loader/config.hpp>

#include <stdexcept>

namespace config_loader {

template <typename T>
T readValue(const YAML::Node& node, const char* key, T defaultValue) {
    if (!node || !node[key]) {
        return defaultValue;
    }
    return node[key].as<T>();
}

access_core::FrameHandlerConfig readValuesFromNode(const YAML::Node& node) {
    access_core::FrameHandlerConfig cfg;
    cfg.antiReplayEnabled = readValue<bool>(node, "anti_replay_enabled", cfg.antiReplayEnabled);
    cfg.replayWindowSize = readValue<size_t>(node, "replay_window_size", cfg.replayWindowSize);
    cfg.maxCtLen = readValue<uint32_t>(node, "max_ct_len", cfg.maxCtLen);
    cfg.maxSkewMs = readValue<uint64_t>(node, "max_skew_ms", cfg.maxSkewMs);
    cfg.allowPreviousKeyVersion = readValue<bool>(node, "allow_previous_key_version", cfg.allowPreviousKeyVersion);
    cfg.enforceReaderDoorBinding = readValue<bool>(node, "enforce_reader_door_binding", cfg.enforceReaderDoorBinding);

    if (cfg.antiReplayEnabled && cfg.replayWindowSize == 0) {
        throw std::runtime_error("config: replay_window_size must be > 0 when anti_replay_enabled");
    }
    return cfg;
}

Config loadFromYaml(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("config: failed to load yaml: ") + e.what());
    }

    Config cfg;
    cfg.frameHandler = readValuesFromNode(root["frame_handler"]);
    return cfg;
}

} // namespace config_loader
