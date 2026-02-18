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

///@todo make a specific load function for each config section
Config loadFromYaml(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("config: failed to load yaml: ") + e.what());
    }

    Config cfg;
    cfg.storage.sqlitePath = readValue<std::string>(root["storage"], "sqlite_path", cfg.storage.sqlitePath);

    // admin
    cfg.admin.bindHost = readValue<std::string>(root["admin"], "bind_host", cfg.admin.bindHost);
    cfg.admin.port = readValue<uint16_t>(root["admin"], "port", cfg.admin.port);
    cfg.admin.adminToken = readValue<std::string>(root["admin"], "admin_token", cfg.admin.adminToken);
    cfg.admin.maxUploadBytes = readValue<size_t>(root["admin"], "max_upload_bytes", cfg.admin.maxUploadBytes);
    cfg.admin.maxEvents = readValue<size_t>(root["admin"], "max_events", cfg.admin.maxEvents);

    // key_management
    cfg.keyManagement.currentKeyVersion =
        readValue<uint32_t>(root["key_management"], "current_key_version", cfg.keyManagement.currentKeyVersion);
    cfg.keyManagement.allowPreviousKeyVersion =
        readValue<bool>(root["key_management"], "allow_previous_key_version", cfg.keyManagement.allowPreviousKeyVersion);
    cfg.keyManagement.masterKeyPath =
        readValue<std::string>(root["key_management"], "master_key_path", cfg.keyManagement.masterKeyPath);

    return cfg;
}

} // namespace config_loader
