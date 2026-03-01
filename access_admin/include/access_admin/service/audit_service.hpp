#pragma once

//! @file audit_service.hpp
//! Service for audit log access and verification.

#include <cstdint>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Retrieves audit log entries with pagination.
//! @param [in,out] app Application state.
//! @param [in] limit Maximum number of entries to return.
//! @param [in] offset Offset for pagination.
//! @return ServiceResult with audit array.
ServiceResult listAuditLog(AppState& app, int limit, int offset);

//! Verifies the audit log chain integrity.
//! @param [in,out] app Application state.
//! @return ServiceResult with ok and error fields.
ServiceResult verifyAuditChain(AppState& app);

}  // namespace admin::service
