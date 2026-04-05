#pragma once

//! @file hw_service.hpp
//! Service for hardware reader endpoints (ESP32/RC522).

#include <cstdint>
#include <optional>
#include <string>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

//! Service functions for the hardware reader endpoint (ESP32/MFRC522).
namespace admin::service {

//! Request from hardware reader.
struct HwUidRequest {
    //! Card UID (hex string).
    std::string uid;
    //! Reader identifier.
    uint32_t reader_id;
    //! Door identifier.
    uint32_t door_id;
    //! Hardware sequence number (anti-replay).
    uint64_t hw_seq;
    //! Action type.
    std::string action = "open";
};

//! Parses HwUidRequest from JSON.
//! @param [in] j JSON object from request body.
//! @param [out] req Parsed request.
//! @return True on success, false on parse error.
bool parseHwUidRequest(const json& j, HwUidRequest& req);

//! Verifies HMAC-SHA256 signature for hardware endpoint.
//! Signature covers: "POST /api/hw/uid\n" + raw JSON body.
//! @param [in] signature_hex Hex-encoded signature from X-HW-Signature header.
//! @param [in] body Raw request body.
//! @param [in] hw_secret_hex 64-char hex secret (empty = misconfigured error).
//! @param [out] err Error message on failure ("misconfigured" if secret empty).
//! @return True if signature is valid, false otherwise.
bool verifyHwSignature(const std::string& signature_hex,
    const std::string& body,
    const std::string& hw_secret_hex,
    std::string& err);

//! Processes a hardware UID scan request.
//! Builds encrypted frame internally and runs through DecisionEngine.
//! @param [in,out] app Application state.
//! @param [in] req Hardware request parameters.
//! @return ServiceResult with allow/reason and frame metadata.
ServiceResult processHwUid(AppState& app, const HwUidRequest& req);

}  // namespace admin::service
