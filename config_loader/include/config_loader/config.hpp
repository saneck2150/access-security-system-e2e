#pragma once
#include <cstdint>
#include <string>

#include <access_core/handle_frame.hpp>
#include <key_manager/key_manager.hpp>
#include <yaml-cpp/yaml.h>

//! Configuration loading from YAML files.
namespace config_loader {

//! Storage layer configuration.
struct StorageConfig {
    //! Path to SQLite database file.
    std::string sqlitePath = "data/access.db";
};

//! HTTP admin API configuration.
struct AdminConfig {
    //! Network interface to bind (e.g., "0.0.0.0" for all).
    std::string bindHost = "127.0.0.1";
    //! HTTP port number.
    uint16_t port = 8080;
    //! Bearer token for admin authentication.
    std::string adminToken = "";
    //! Maximum file upload size in bytes.
    size_t maxUploadBytes = 20 * 1024 * 1024;
    //! Maximum events to keep in circular buffer.
    size_t maxEvents = 1024;
};

//! Key management configuration.
struct KeyManagementYaml {
    //! Active key version for encryption.
    uint32_t currentKeyVersion = 1;
    //! Allow decryption with previous key version.
    bool allowPreviousKeyVersion = true;
    //! Path to hex-encoded master key file.
    std::string masterKeyPath = "secrets/master_key.hex";
};

//! Complete application configuration.
struct Config {
    //! Frame handler settings (anti-replay, timing, etc.).
    access_core::FrameHandlerConfig frameHandler{};
    //! Storage layer settings.
    StorageConfig storage{};
    //! Admin API settings.
    AdminConfig admin{};
    //! Key management settings.
    KeyManagementYaml keyManagement{};
};

//! Loads configuration from a YAML file.
//! @param [in] path Path to the YAML configuration file.
//! @return Parsed configuration struct.
//! @throws std::runtime_error If file cannot be loaded or validation fails.
Config loadFromYaml(const std::string& path);

}  // namespace config_loader
