#pragma once

//! @file simulate_service.hpp
//! Service for simulating card scans.

#include <cstdint>
#include <optional>
#include <string>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Parameters for scan simulation.
struct SimulateScanRequest {
    std::string card_id;                  //!< Card identifier.
    uint32_t reader_id;                   //!< Reader identifier.
    uint32_t door_id;                     //!< Door identifier.
    std::string action = "open";          //!< Action type.
    std::optional<uint32_t> key_version;  //!< Key version override.
    std::optional<uint64_t> ts_unix_ms;   //!< Timestamp override.
    std::optional<uint64_t> seq;          //!< Sequence number override.
};

//! Parses SimulateScanRequest from JSON.
//! @param [in] j JSON object.
//! @param [out] req Parsed request.
//! @return True on success, false on parse error.
bool parseSimulateScanRequest(const json& j, SimulateScanRequest& req);

//! Simulates a card scan with encrypted frame.
//! @param [in,out] app Application state.
//! @param [in] req Scan request parameters.
//! @return ServiceResult with decision and frame details.
ServiceResult simulateScan(AppState& app, const SimulateScanRequest& req);

}  // namespace admin::service
