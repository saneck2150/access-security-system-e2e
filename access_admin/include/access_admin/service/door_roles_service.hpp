#pragma once

//! @file door_roles_service.hpp
//! Service for door role management.

#include <cstdint>
#include <string>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Lists all door-role mappings.
//! @param [in,out] app Application state.
//! @return ServiceResult with door_roles array.
ServiceResult listDoorRoles(AppState& app);

//! Allows a role to access a door.
//! @param [in,out] app Application state.
//! @param [in] door_id Door identifier.
//! @param [in] role Role name.
//! @return ServiceResult indicating success.
ServiceResult allowRole(AppState& app, uint32_t door_id, const std::string& role);

//! Revokes a role's access to a door.
//! @param [in,out] app Application state.
//! @param [in] door_id Door identifier.
//! @param [in] role Role name.
//! @return ServiceResult indicating success.
ServiceResult revokeRole(AppState& app, uint32_t door_id, const std::string& role);

}  // namespace admin::service
