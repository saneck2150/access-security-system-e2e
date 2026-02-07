#include "access_decision/payload.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace access_decision {

AccessRequest parse_access_request_json(std::string_view json_text) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_text.begin(), json_text.end());
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("payload: invalid json: ") + e.what());
    }

    if (!j.is_object())
        throw std::runtime_error("payload: json must be object");

    AccessRequest r;

    if (!j.contains("card_id") || !j["card_id"].is_string()) {
        throw std::runtime_error("payload: missing/invalid card_id");
    }
    if (!j.contains("action") || !j["action"].is_string()) {
        throw std::runtime_error("payload: missing/invalid action");
    }

    r.card_id = j["card_id"].get<std::string>();
    r.action = j["action"].get<std::string>();

    if (r.card_id.empty())
        throw std::runtime_error("payload: card_id empty");
    if (r.action.empty())
        throw std::runtime_error("payload: action empty");

    return r;
}

}  // namespace access_decision
