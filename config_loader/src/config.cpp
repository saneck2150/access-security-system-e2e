#include <config_loader/config.hpp>

#include <yaml-cpp/yaml.h>
#include <stdexcept>

namespace config_loader {

static size_t read_size_t(const YAML::Node& n, const char* key, size_t def) {
    if (!n || !n[key]) return def;
    return n[key].as<size_t>();
}

static bool read_bool(const YAML::Node& n, const char* key, bool def) {
    if (!n || !n[key]) return def;
    return n[key].as<bool>();
}

Config load_from_yaml(const std::string& path) {
    Config cfg;

    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("config: failed to load yaml: ") + e.what());
    }

    const auto hf = root["handle_frame"];
    cfg.handle_frame.anti_replay_enabled =
        read_bool(hf, "anti_replay_enabled", cfg.handle_frame.anti_replay_enabled);

    cfg.handle_frame.replay_window_size =
        read_size_t(hf, "replay_window_size", cfg.handle_frame.replay_window_size);

    if (cfg.handle_frame.anti_replay_enabled && cfg.handle_frame.replay_window_size == 0) {
    }

    return cfg;
}

} // namespace config_loader
