#pragma once

//! @file policy.hpp
//! In-memory access policy for testing and simple deployments.

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace access_decision {

//! Simple in-memory RBAC policy container.
//! Maps cards to roles and roles to doors.
class AccessPolicy {
  public:
    //! Associates a card with a role.
    //! @param [in] cardId The card identifier.
    //! @param [in] role   The role to assign.
    void addCard(std::string cardId, std::string role);

    //! Grants a role access to a door.
    //! @param [in] doorId The door identifier.
    //! @param [in] role   The role to allow.
    void allowRole(uint32_t doorId, std::string role);

    //! Looks up the role for a card.
    //! @param [in] cardId The card identifier.
    //! @return The role string, or empty if not found.
    std::string roleForCard(const std::string& cardId) const;

    //! Checks if a role is allowed for a door.
    //! @param [in] doorId The door identifier.
    //! @param [in] role   The role to check.
    //! @return True if the role has access.
    bool isAllowed(uint32_t doorId, const std::string& role) const;

  private:
    std::unordered_map<std::string, std::string> _cardToRole;
    std::unordered_map<uint32_t, std::unordered_set<std::string>> _doorAllowedRoles;
};

}  // namespace access_decision
