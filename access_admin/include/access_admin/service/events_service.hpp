#pragma once

//! @file events_service.hpp
//! Service for real-time event polling.

#include <cstdint>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Retrieves events after a given ID.
//! @param [in] app Application state.
//! @param [in] after_id Return events with ID greater than this.
//! @param [in] limit Maximum number of events to return.
//! @return ServiceResult with events array and last_id.
ServiceResult getEvents(AppState& app, uint64_t after_id, size_t limit);

}  // namespace admin::service
