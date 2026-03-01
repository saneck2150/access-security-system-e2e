#pragma once

//! @file payload.hpp
//! JSON payload parsing for access requests.

#include <string>
#include <string_view>

namespace access_decision {

//! Parsed access request from the frame payload.
struct AccessRequest {
    std::string cardId;  //!< Raw card UID.
    std::string action;  //!< Requested action (e.g., "open").
};

//! Parses a JSON access request payload.
//! Expected format: {"card_id": "...", "action": "open"}
//! @param [in] jsonText JSON string from decrypted frame payload.
//! @return Parsed AccessRequest.
AccessRequest parseAccessRequestJson(std::string_view jsonText);

}  // namespace access_decision
