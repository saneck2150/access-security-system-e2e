#pragma once
#include <access_core/handle_frame.hpp>
#include <key_manager/key_manager.hpp>

#include <yaml-cpp/yaml.h>

#include <cstdint>
#include <string>

namespace config_loader {

struct StorageConfig {
    std::string sqlitePath = "data/access.db";
};

struct AdminConfig {
    std::string bindHost = "127.0.0.1";
    uint16_t port = 8080;
    std::string adminToken = "";          
    size_t maxUploadBytes = 20 * 1024 * 1024;
    size_t maxEvents = 1024;
};

struct KeyManagementYaml {
    uint32_t currentKeyVersion = 1;
    bool allowPreviousKeyVersion = true;
    std::string masterKeyPath = "secrets/master_key.hex";
};

struct Config {
    access_core::FrameHandlerConfig frameHandler{};
    StorageConfig storage{};
    AdminConfig admin{};
    KeyManagementYaml keyManagement{};
};

Config loadFromYaml(const std::string& path);

} // namespace config_loader
