#include <stdexcept>

#include <config_loader/config.hpp>

namespace config_loader {

namespace {

template <typename T>
T readValue(const YAML::Node& node, const char* key, T defaultValue) {
    if (!node || !node[key]) {
        return defaultValue;
    }
    return node[key].as<T>();
}

access_core::FrameHandlerConfig loadFrameHandler(const YAML::Node& node) {
    access_core::FrameHandlerConfig cfg;
    cfg.antiReplayEnabled = readValue<bool>(node, "anti_replay_enabled", cfg.antiReplayEnabled);
    cfg.replayWindowSize = readValue<size_t>(node, "replay_window_size", cfg.replayWindowSize);
    cfg.maxCtLen = readValue<uint32_t>(node, "max_ct_len", cfg.maxCtLen);
    cfg.maxSkewMs = readValue<uint64_t>(node, "max_skew_ms", cfg.maxSkewMs);
    cfg.allowPreviousKeyVersion =
        readValue<bool>(node, "allow_previous_key_version", cfg.allowPreviousKeyVersion);
    cfg.enforceReaderDoorBinding =
        readValue<bool>(node, "enforce_reader_door_binding", cfg.enforceReaderDoorBinding);

    if (cfg.antiReplayEnabled && cfg.replayWindowSize == 0) {
        throw std::runtime_error("config: replay_window_size must be > 0 when anti_replay_enabled");
    }
    return cfg;
}

StorageConfig loadStorage(const YAML::Node& node) {
    StorageConfig cfg;
    cfg.sqlitePath = readValue<std::string>(node, "sqlite_path", cfg.sqlitePath);
    return cfg;
}

AdminConfig loadAdmin(const YAML::Node& node) {
    AdminConfig cfg;
    cfg.bindHost = readValue<std::string>(node, "bind_host", cfg.bindHost);
    cfg.port = readValue<uint16_t>(node, "port", cfg.port);
    cfg.adminToken = readValue<std::string>(node, "admin_token", cfg.adminToken);
    cfg.hwSharedSecretHex =
        readValue<std::string>(node, "hw_shared_secret_hex", cfg.hwSharedSecretHex);
    cfg.maxUploadBytes = readValue<size_t>(node, "max_upload_bytes", cfg.maxUploadBytes);
    cfg.maxEvents = readValue<size_t>(node, "max_events", cfg.maxEvents);
    return cfg;
}

KeyManagementYaml loadKeyManagement(const YAML::Node& node) {
    KeyManagementYaml cfg;
    cfg.currentKeyVersion = readValue<uint32_t>(node, "current_key_version", cfg.currentKeyVersion);
    cfg.allowPreviousKeyVersion =
        readValue<bool>(node, "allow_previous_key_version", cfg.allowPreviousKeyVersion);
    cfg.masterKeyPath = readValue<std::string>(node, "master_key_path", cfg.masterKeyPath);
    return cfg;
}

ExperimentConfig loadExperiment(const YAML::Node& node) {
    ExperimentConfig cfg;
    cfg.cipherMode = readValue<std::string>(node, "cipher_mode", cfg.cipherMode);
    cfg.nonceMode = readValue<std::string>(node, "nonce_mode", cfg.nonceMode);
    cfg.keyDerivationMode =
        readValue<std::string>(node, "key_derivation_mode", cfg.keyDerivationMode);
    cfg.aadMode = readValue<std::string>(node, "aad_mode", cfg.aadMode);
    cfg.pepperMode = readValue<std::string>(node, "pepper_mode", cfg.pepperMode);
    cfg.auditChainEnabled = readValue<bool>(node, "audit_chain_enabled", cfg.auditChainEnabled);
    cfg.misuseDetectionEnabled =
        readValue<bool>(node, "misuse_detection_enabled", cfg.misuseDetectionEnabled);
    cfg.rollbackThreshold =
        readValue<uint64_t>(node, "rollback_threshold", cfg.rollbackThreshold);
    cfg.tagFailStreakLimit =
        readValue<uint32_t>(node, "tag_fail_streak_limit", cfg.tagFailStreakLimit);
    return cfg;
}

}  // namespace

Config loadFromYaml(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("config: failed to load yaml: ") + e.what());
    }

    Config cfg;
    cfg.frameHandler = loadFrameHandler(root["frame_handler"]);
    cfg.storage = loadStorage(root["storage"]);
    cfg.admin = loadAdmin(root["admin"]);
    cfg.keyManagement = loadKeyManagement(root["key_management"]);
    cfg.experiment = loadExperiment(root["experiment"]);
    return cfg;
}

}  // namespace config_loader
