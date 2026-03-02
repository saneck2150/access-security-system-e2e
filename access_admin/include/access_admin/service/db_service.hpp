#pragma once

//! @file db_service.hpp
//! Service for database export and import.

#include <string>
#include <vector>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Result of database export.
struct DbExportResult {
    bool ok = true;          //! Operation success flag.
    int http_status = 200;   //! HTTP status code.
    std::string error;       //! Error message if failed.
    std::vector<char> data;  //! Database file contents.
};

//! Exports the database file.
//! @param [in,out] app Application state.
//! @return DbExportResult with file contents.
DbExportResult exportDatabase(AppState& app);

//! Imports a database file.
//! @param [in,out] app Application state.
//! @param [in] data Database file contents.
//! @return ServiceResult indicating success.
ServiceResult importDatabase(AppState& app, const std::string& data);

}  // namespace admin::service
