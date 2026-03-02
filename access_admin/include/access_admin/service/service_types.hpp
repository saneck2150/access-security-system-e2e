#pragma once

//! @file service_types.hpp
//! Common types and constants for admin services.

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace admin::service {

using json = nlohmann::json;

//! Result of a service operation.
struct ServiceResult {
    bool ok = true;         //! Operation success flag.
    int http_status = 200;  //! HTTP status code.
    json body;              //! W Response JSON body.
};

//! HTTP status codes.
constexpr int kHttpOk = 200;
constexpr int kHttpRedirect = 302;
constexpr int kHttpBadRequest = 400;
constexpr int kHttpUnauthorized = 401;
constexpr int kHttpPayloadTooLarge = 413;
constexpr int kHttpServerError = 500;

//! Default pagination limit for API responses.
constexpr size_t kDefaultLimit = 200;

//! Default offset for paginated queries.
constexpr size_t kDefaultOffset = 0;

//! Creates an error result.
//! @param [in] message Error message.
//! @param [in] status HTTP status code.
//! @return ServiceResult with error.
ServiceResult errorResult(const std::string& message, int status = kHttpBadRequest);

//! Creates a success result.
//! @param [in] body Response JSON body.
//! @return ServiceResult with success.
ServiceResult okResult(const json& body);

}  // namespace admin::service
