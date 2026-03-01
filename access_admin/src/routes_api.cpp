#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <access_admin/routes_api.hpp>
#include <access_admin/service/access_service.hpp>
#include <access_admin/service/audit_service.hpp>
#include <access_admin/service/cards_service.hpp>
#include <access_admin/service/db_service.hpp>
#include <access_admin/service/door_roles_service.hpp>
#include <access_admin/service/events_service.hpp>
#include <access_admin/service/readers_service.hpp>
#include <access_admin/service/service_types.hpp>
#include <access_admin/service/simulate_service.hpp>

namespace admin {

using json = nlohmann::json;
using namespace service;

namespace {

//! Sends a ServiceResult as HTTP response.
void sendResult(httplib::Response& res, const ServiceResult& r) {
    setJson(res, r.body, r.http_status);
}

//! Checks authorization and returns error if unauthorized.
//! @return True if authorized, false otherwise.
bool requireAuth(const httplib::Request& req, httplib::Response& res, const std::string& token) {
    if (!checkAuth(req, token)) {
        sendResult(res, errorResult("unauthorized", kHttpUnauthorized));
        return false;
    }
    return true;
}

}  // namespace

void registerRoutes(httplib::Server& svr, AppState& app) {
    // UI: redirect to static
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.status = kHttpRedirect;
        res.set_header("Location", "/static/index.html");
    });

    // Serve /static from web folder
    svr.set_mount_point("/static", "web");

    // ---- events ----
    svr.Get("/api/events", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }

        uint64_t after = req.has_param("after") ? std::stoull(req.get_param_value("after")) : 0;
        size_t limit = req.has_param("limit")
                           ? static_cast<size_t>(std::stoull(req.get_param_value("limit")))
                           : kDefaultLimit;

        sendResult(res, getEvents(app, after, limit));
    });

    // ---- simulate ----
    svr.Post("/api/simulate_scan", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }

        try {
            auto j = json::parse(req.body);
            SimulateScanRequest scanReq;
            if (!parseSimulateScanRequest(j, scanReq)) {
                sendResult(res, errorResult("invalid request", kHttpBadRequest));
                return;
            }
            sendResult(res, simulateScan(app, scanReq));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpBadRequest));
        }
    });

    // ---- readers ----
    svr.Get("/api/readers", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        sendResult(res, listReaders(app));
    });

    svr.Post("/api/readers", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        try {
            auto j = json::parse(req.body);
            sendResult(res,
                       upsertReader(app,
                                    j.at("reader_id").get<uint32_t>(),
                                    j.at("current_key_version").get<uint32_t>()));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpBadRequest));
        }
    });

    svr.Delete(R"(/api/readers/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        try {
            sendResult(res, deleteReader(app, static_cast<uint32_t>(std::stoul(req.matches[1]))));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpServerError));
        }
    });

    svr.Post(R"(/api/readers/(\d+)/doors)",
             [&](const httplib::Request& req, httplib::Response& res) {
                 if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
                     return;
                 }
                 try {
                     auto j = json::parse(req.body);
                     sendResult(res,
                                bindDoor(app,
                                         static_cast<uint32_t>(std::stoul(req.matches[1])),
                                         j.at("door_id").get<uint32_t>()));
                 } catch (const std::exception& e) {
                     sendResult(res, errorResult(e.what(), kHttpBadRequest));
                 }
             });

    svr.Delete(R"(/api/readers/(\d+)/doors/(\d+))",
               [&](const httplib::Request& req, httplib::Response& res) {
                   if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
                       return;
                   }
                   try {
                       sendResult(res,
                                  unbindDoor(app,
                                             static_cast<uint32_t>(std::stoul(req.matches[1])),
                                             static_cast<uint32_t>(std::stoul(req.matches[2]))));
                   } catch (const std::exception& e) {
                       sendResult(res, errorResult(e.what(), kHttpServerError));
                   }
               });

    // ---- door_roles ----
    svr.Get("/api/door_roles", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        sendResult(res, listDoorRoles(app));
    });

    svr.Post("/api/door_roles", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        try {
            auto j = json::parse(req.body);
            sendResult(
                res,
                allowRole(app, j.at("door_id").get<uint32_t>(), j.at("role").get<std::string>()));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpBadRequest));
        }
    });

    svr.Delete("/api/door_roles", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        try {
            auto j = json::parse(req.body);
            sendResult(
                res,
                revokeRole(app, j.at("door_id").get<uint32_t>(), j.at("role").get<std::string>()));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpBadRequest));
        }
    });

    // ---- cards ----
    svr.Get("/api/cards", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        size_t limit = req.has_param("limit")
                           ? static_cast<size_t>(std::stoull(req.get_param_value("limit")))
                           : kDefaultLimit;
        size_t offset = req.has_param("offset")
                            ? static_cast<size_t>(std::stoull(req.get_param_value("offset")))
                            : 0;
        sendResult(res, listCards(app, limit, offset));
    });

    svr.Post("/api/cards", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        try {
            auto j = json::parse(req.body);
            std::optional<uint32_t> kv;
            if (j.contains("key_version")) {
                kv = j.at("key_version").get<uint32_t>();
            }
            sendResult(
                res,
                upsertCard(
                    app, j.at("card_id").get<std::string>(), j.at("role").get<std::string>(), kv));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpBadRequest));
        }
    });

    svr.Delete("/api/cards", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        try {
            auto j = json::parse(req.body);
            sendResult(res, deleteCard(app, j.at("card_hmac").get<std::string>()));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpBadRequest));
        }
    });

    // ---- audit ----
    svr.Get("/api/audit", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        int limit = req.has_param("limit") ? std::stoi(req.get_param_value("limit"))
                                           : static_cast<int>(kDefaultLimit);
        int offset = req.has_param("offset") ? std::stoi(req.get_param_value("offset")) : 0;
        sendResult(res, listAuditLog(app, limit, offset));
    });

    svr.Post("/api/audit/verify", [&](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        sendResult(res, verifyAuditChain(app));
    });

    // ---- db ----
    svr.Get("/api/db/export", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }
        auto result = exportDatabase(app);
        if (!result.ok) {
            res.status = result.http_status;
            res.set_content(result.error, "text/plain");
            return;
        }
        res.set_header("Content-Disposition", "attachment; filename=\"access.db\"");
        res.set_content(std::string(result.data.begin(), result.data.end()),
                        "application/octet-stream");
    });

    svr.Post("/api/db/import", [&](const httplib::Request& req, httplib::Response& res) {
        if (!requireAuth(req, res, app.cfg.admin.adminToken)) {
            return;
        }

        if (!req.is_multipart_form_data() || !req.form.has_file("db")) {
            res.status = kHttpBadRequest;
            res.set_content("expected multipart form-data with file field 'db'", "text/plain");
            return;
        }
        const auto file = req.form.get_file("db");
        auto result = importDatabase(app, file.content);
        if (!result.ok) {
            res.status = result.http_status;
            res.set_content(result.body.value("error", "unknown error"), "text/plain");
            return;
        }
        res.set_content(result.body.value("message", "OK"), "text/plain");
    });

    // ---- access/check ----
    svr.Post("/api/access/check", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            auto bytes = hexToBytes(j.at("frame_hex").get<std::string>());
            sendResult(res, checkAccess(app, bytes));
        } catch (const std::exception& e) {
            sendResult(res, errorResult(e.what(), kHttpBadRequest));
        }
    });
}

void registerAllRoutes(httplib::Server& svr, AppState& app) {
    registerRoutes(svr, app);
}

}  // namespace admin
