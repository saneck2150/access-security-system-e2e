#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace access_decision {

class AccessPolicy {
  public:
    void add_card(std::string card_id, std::string role);
    void allow_role(uint32_t door_id, std::string role);

    std::string role_for_card(const std::string& card_id) const;

    bool is_allowed(uint32_t door_id, const std::string& role) const;

  private:
    std::unordered_map<std::string, std::string> _card_to_role;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> _door_allowed_roles;
};

}  // namespace access_decision
