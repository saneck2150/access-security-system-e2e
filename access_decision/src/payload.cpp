#include "access_decision/payload.hpp"

#include <stdexcept>

#include <nlohmann/json.hpp>

namespace access_decision {

AccessRequest parseAccessRequestJson(std::string_view jsonText) {
    nlohmann::json json;
    try {
        json = nlohmann::json::parse(jsonText.begin(), jsonText.end());
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("payload: invalid json: ") + e.what());
    }

    if (!json.is_object()) {
        throw std::runtime_error("payload: json must be object");
    }

    AccessRequest request;

    if (!json.contains("card_id") || !json["card_id"].is_string()) {
        throw std::runtime_error("payload: missing/invalid card_id");
    }
    if (!json.contains("action") || !json["action"].is_string()) {
        throw std::runtime_error("payload: missing/invalid action");
    }

    request.cardId = json["card_id"].get<std::string>();
    request.action = json["action"].get<std::string>();

    if (request.cardId.empty()) {
        throw std::runtime_error("payload: card_id empty");
    }
    if (request.action.empty()) {
        throw std::runtime_error("payload: action empty");
    }

    return request;
}

}  // namespace access_decision
