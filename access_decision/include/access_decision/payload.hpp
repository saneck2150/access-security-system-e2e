#pragma once

#include <string>
#include <string_view>

namespace access_decision {

struct AccessRequest {
    std::string cardId;
    std::string action;
};

AccessRequest parseAccessRequestJson(std::string_view jsonText);

} // namespace access_decision
