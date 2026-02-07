#pragma once
#include <string>
#include <string_view>

namespace access_decision {

struct AccessRequest {
    std::string card_id;
    std::string action;
};

AccessRequest parse_access_request_json(std::string_view json_text);

}  // namespace access_decision
