#pragma once
#include <access_core/handle_frame.hpp>

#include <yaml-cpp/yaml.h>

#include <string>

namespace config_loader {

struct Config {
    access_core::FrameHandlerConfig frameHandler{};
};

Config loadFromYaml(const std::string& path);
access_core::FrameHandlerConfig readValuesFromNode(const YAML::Node& node);

} // namespace config_loader
