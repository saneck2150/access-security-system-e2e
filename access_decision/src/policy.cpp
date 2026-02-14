#include "access_decision/policy.hpp"

namespace access_decision {

void AccessPolicy::addCard(std::string cardId, std::string role) {
    _cardToRole.emplace(std::move(cardId), std::move(role));
}

void AccessPolicy::allowRole(uint32_t doorId, std::string role) {
    _doorAllowedRoles[doorId].insert(std::move(role));
}

std::string AccessPolicy::roleForCard(const std::string& cardId) const {
    auto it = _cardToRole.find(cardId);
    if (it == _cardToRole.end()) {
        return {};
    }
    return it->second;
}

bool AccessPolicy::isAllowed(uint32_t doorId, const std::string& role) const {
    auto it = _doorAllowedRoles.find(doorId);
    if (it == _doorAllowedRoles.end()) {
        return false;
    }
    return it->second.count(role) != 0;
}

} // namespace access_decision
