#include "access_decision/policy.hpp"

namespace access_decision {

void AccessPolicy::add_card(std::string card_id, std::string role) {
    _card_to_role.emplace(std::move(card_id), std::move(role));
}

void AccessPolicy::allow_role(uint32_t door_id, std::string role) {
    _door_allowed_roles[door_id].insert(std::move(role));
}

std::string AccessPolicy::role_for_card(const std::string& card_id) const {
    auto it = _card_to_role.find(card_id);
    if (it == _card_to_role.end())
        return {};
    return it->second;
}

bool AccessPolicy::is_allowed(uint32_t door_id, const std::string& role) const {
    auto it = _door_allowed_roles.find(door_id);
    if (it == _door_allowed_roles.end())
        return false;
    return it->second.count(role) != 0;
}

}  // namespace access_decision
