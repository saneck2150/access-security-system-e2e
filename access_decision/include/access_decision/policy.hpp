#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace access_decision {

class AccessPolicy {
  public:
    void addCard(std::string cardId, std::string role);
    void allowRole(uint32_t doorId, std::string role);

    std::string roleForCard(const std::string& cardId) const;
    bool isAllowed(uint32_t doorId, const std::string& role) const;

  private:
    std::unordered_map<std::string, std::string> _cardToRole;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> _doorAllowedRoles;
};

} // namespace access_decision
