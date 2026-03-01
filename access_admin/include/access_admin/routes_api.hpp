#pragma once

//! @file routes_api.hpp
//! HTTP route registration for the admin API.

#include <httplib.h>

namespace admin {

struct AppState;

//! Registers all API routes on the HTTP server.
//! @param [in,out] svr HTTP server instance.
//! @param [in,out] app Application state.
void registerRoutes(httplib::Server& svr, AppState& app);

//! Registers all routes (wrapper for external use).
//! @param [in,out] svr HTTP server instance.
//! @param [in,out] app Application state.
void registerAllRoutes(httplib::Server& svr, AppState& app);

}  // namespace admin
