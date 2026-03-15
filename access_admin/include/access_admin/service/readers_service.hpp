#pragma once

//! @file readers_service.hpp
//! Service for reader and door management.

#include <cstdint>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Lists all readers with their doors.
//! @param [in,out] app Application state.
//! @return ServiceResult with readers array.
ServiceResult listReaders(AppState& app);

//! Creates or updates a reader.
//! @param [in,out] app Application state.
//! @param [in] reader_id Reader identifier.
//! @param [in] key_version Current key version.
//! @return ServiceResult indicating success.
ServiceResult upsertReader(AppState& app, uint32_t reader_id, uint32_t key_version);

//! Deletes a reader.
//! @param [in,out] app Application state.
//! @param [in] reader_id Reader identifier.
//! @return ServiceResult indicating success.
ServiceResult deleteReader(AppState& app, uint32_t reader_id);

//! Binds a door to a reader.
//! @param [in,out] app Application state.
//! @param [in] reader_id Reader identifier.
//! @param [in] door_id Door identifier.
//! @return ServiceResult indicating success.
ServiceResult bindDoor(AppState& app, uint32_t reader_id, uint32_t door_id);

//! Unbinds a door from a reader.
//! @param [in,out] app Application state.
//! @param [in] reader_id Reader identifier.
//! @param [in] door_id Door identifier.
//! @return ServiceResult indicating success.
ServiceResult unbindDoor(AppState& app, uint32_t reader_id, uint32_t door_id);

//! Removes quarantine from a reader (R2 admin action).
//! @param [in,out] app Application state.
//! @param [in] reader_id Reader to unquarantine.
//! @return ServiceResult with ok=true if was quarantined, error if not.
ServiceResult unquarantineReader(AppState& app, uint32_t reader_id);

}  // namespace admin::service
