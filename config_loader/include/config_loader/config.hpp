#pragma once
#include <access_core/handle_frame.hpp>
#include <string>

namespace config_loader {

struct Config {
    access_core::HandleFrameConfig handle_frame{};
};

Config load_from_yaml(const std::string& path);

} // namespace config_loader
