#pragma once

//! @file access_service.hpp
//! Service for access check operations.

#include <cstdint>
#include <vector>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Checks access for a raw encrypted frame.
//! @param [in,out] app Application state.
//! @param [in] frame_bytes Raw encrypted frame bytes.
//! @return ServiceResult with allow and reason.
ServiceResult checkAccess(AppState& app, const std::vector<uint8_t>& frame_bytes);

}  // namespace admin::service
