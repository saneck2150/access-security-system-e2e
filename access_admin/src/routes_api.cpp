#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>

#include <access_storage/audit_verify.hpp>
#include <access_decision/card_id_hasher.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>

/// @todo split into multiple files
namespace admin {

static void registerRoutes(httplib::Server& svr, AppState& app) {
    // UI: redirect to static
    svr.Get("/", [&](const httplib::Request&, httplib::Response& res) {
        res.status = 302;
        res.set_header("Location", "/static/index.html");
    });

    // Serve /static from web folder (run binary from repo root, or adjust path)
    svr.set_mount_point("/static", "web");

    // ---- events ----
    svr.Get("/api/events", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }

        uint64_t after = req.has_param("after") ? std::stoull(req.get_param_value("after")) : 0;
        size_t limit = req.has_param("limit") ? static_cast<size_t>(std::stoull(req.get_param_value("limit"))) : 200;

        auto evs = app.events.getAfter(after, limit);
        json out;
        out["last_id"] = app.events.lastId();
        out["events"] = json::array();
        for (const auto& e : evs) {
            out["events"].push_back({
                {"id", e.id},
                {"ts_unix_ms", e.ts_unix_ms},
                {"kind", e.kind},
                {"message", e.message},
                {"reader_id", e.reader_id},
                {"door_id", e.door_id},
                {"seq", e.seq},
                {"allow", e.allow},
                {"reason", e.reason},
            });
        }
        setJson(res, out);
    });

    // ---- readers ----
    svr.Get("/api/readers", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }

        std::lock_guard<std::mutex> lk(app.m);
        const auto readers = app.store->listReaders();
        const auto doors = app.store->listReaderDoors(0);

        std::unordered_map<uint32_t, std::vector<uint32_t>> byReader;
        for (const auto& d : doors) byReader[d.reader_id].push_back(d.door_id);

        json out;
        out["readers"] = json::array();
        for (const auto& r : readers) {
            out["readers"].push_back({
                {"reader_id", r.reader_id},
                {"current_key_version", r.current_key_version},
                {"doors", byReader[r.reader_id]}
            });
        }
        setJson(res, out);
    });

    svr.Post("/api/readers", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        try {
            auto j = json::parse(req.body);
            const uint32_t rid = j.at("reader_id").get<uint32_t>();
            const uint32_t kv  = j.at("current_key_version").get<uint32_t>();

            std::lock_guard<std::mutex> lk(app.m);
            app.store->upsertReader(rid, kv);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="upsertReader", .reader_id=rid});
            setJson(res, {{"ok", true}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 400);
        }
    });

    svr.Delete(R"(/api/readers/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        const uint32_t rid = static_cast<uint32_t>(std::stoul(req.matches[1]));
        try {
            std::lock_guard<std::mutex> lk(app.m);
            app.store->deleteReader(rid);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="deleteReader", .reader_id=rid});
            setJson(res, {{"ok", true}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 500);
        }
    });

    svr.Post(R"(/api/readers/(\d+)/doors)", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        const uint32_t rid = static_cast<uint32_t>(std::stoul(req.matches[1]));
        try {
            auto j = json::parse(req.body);
            const uint32_t did = j.at("door_id").get<uint32_t>();

            std::lock_guard<std::mutex> lk(app.m);
            app.store->allowDoorForReader(rid, did);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="bindDoor", .reader_id=rid, .door_id=did});
            setJson(res, {{"ok", true}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 400);
        }
    });

    svr.Delete(R"(/api/readers/(\d+)/doors/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        const uint32_t rid = static_cast<uint32_t>(std::stoul(req.matches[1]));
        const uint32_t did = static_cast<uint32_t>(std::stoul(req.matches[2]));
        try {
            std::lock_guard<std::mutex> lk(app.m);
            app.store->revokeDoorForReader(rid, did);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="unbindDoor", .reader_id=rid, .door_id=did});
            setJson(res, {{"ok", true}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 500);
        }
    });

    // ---- door_roles ----
    svr.Get("/api/door_roles", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        std::lock_guard<std::mutex> lk(app.m);
        auto rows = app.store->listDoorRoles(0);
        json out;
        out["door_roles"] = json::array();
        for (auto& r : rows) out["door_roles"].push_back({{"door_id", r.door_id}, {"role", r.role}});
        setJson(res, out);
    });

    svr.Post("/api/door_roles", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        try {
            auto j = json::parse(req.body);
            const uint32_t did = j.at("door_id").get<uint32_t>();
            const std::string role = j.at("role").get<std::string>();

            std::lock_guard<std::mutex> lk(app.m);
            app.store->allowRole(did, role);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="allowRole: " + role, .door_id=did});
            setJson(res, {{"ok", true}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 400);
        }
    });

    svr.Delete("/api/door_roles", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        try {
            auto j = json::parse(req.body);
            const uint32_t did = j.at("door_id").get<uint32_t>();
            const std::string role = j.at("role").get<std::string>();

            std::lock_guard<std::mutex> lk(app.m);
            app.store->revokeRole(did, role);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="revokeRole: " + role, .door_id=did});
            setJson(res, {{"ok", true}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 400);
        }
    });

    // ---- cards ----
    svr.Get("/api/cards", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }

        size_t limit = req.has_param("limit") ? static_cast<size_t>(std::stoull(req.get_param_value("limit"))) : 200;
        size_t offset = req.has_param("offset") ? static_cast<size_t>(std::stoull(req.get_param_value("offset"))) : 0;

        std::lock_guard<std::mutex> lk(app.m);
        auto rows = app.store->listCards(limit, offset);
        json out;
        out["cards"] = json::array();
        for (auto& r : rows) out["cards"].push_back({{"card_hmac", r.card_hmac}, {"role", r.role}});
        setJson(res, out);
    });

    svr.Post("/api/cards", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        try {
            auto j = json::parse(req.body);
            const std::string cardId = j.at("card_id").get<std::string>();
            const std::string role   = j.at("role").get<std::string>();
            uint32_t kv = app.cfg.keyManagement.currentKeyVersion;
            if (j.contains("key_version")) kv = j.at("key_version").get<uint32_t>();

            const auto pepper = app.keyManager.deriveCardPepper(kv);
            access_decision::CardIdHasher hasher(pepper);
            const std::string hmacHex = hasher.hmacHex(cardId);

            std::lock_guard<std::mutex> lk(app.m);
            app.store->upsertCardHmac(hmacHex, role);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="upsertCard role=" + role});
            setJson(res, {{"ok", true}, {"card_hmac", hmacHex}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 400);
        }
    });

    svr.Delete("/api/cards", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }
        try {
            auto j = json::parse(req.body);
            const std::string h = j.at("card_hmac").get<std::string>();

            std::lock_guard<std::mutex> lk(app.m);
            app.store->deleteCardHmac(h);
            app.events.push({.ts_unix_ms=nowUnixMs(), .kind="admin", .message="deleteCard"});
            setJson(res, {{"ok", true}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 400);
        }
    });

    // ---- audit viewer + verify ----
    svr.Get("/api/audit", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }

        int limit = req.has_param("limit") ? std::stoi(req.get_param_value("limit")) : 200;
        int offset = req.has_param("offset") ? std::stoi(req.get_param_value("offset")) : 0;

        std::lock_guard<std::mutex> lk(app.m);
        sqlite3* db = app.store->dbHandle();

        const char* sql =
            "SELECT id, ts_unix_ms, reader_id, door_id, seq, allow, reason, card_hmac, action "
            "FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?;";

        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
            setJson(res, {{"error","prepare failed"}}, 500);
            return;
        }
        sqlite3_bind_int(st, 1, limit);
        sqlite3_bind_int(st, 2, offset);

        json out;
        out["audit"] = json::array();
        while (sqlite3_step(st) == SQLITE_ROW) {
            json row;
            row["id"] = sqlite3_column_int64(st, 0);
            row["ts_unix_ms"] = sqlite3_column_int64(st, 1);
            row["reader_id"] = sqlite3_column_int(st, 2);
            row["door_id"] = sqlite3_column_int(st, 3);
            row["seq"] = sqlite3_column_int64(st, 4);
            row["allow"] = (sqlite3_column_int(st, 5) != 0);

            const unsigned char* reason = sqlite3_column_text(st, 6);
            row["reason"] = reason ? reinterpret_cast<const char*>(reason) : "";

            const unsigned char* ch = sqlite3_column_text(st, 7);
            const unsigned char* act = sqlite3_column_text(st, 8);
            row["card_hmac"] = ch ? reinterpret_cast<const char*>(ch) : "";
            row["action"] = act ? reinterpret_cast<const char*>(act) : "";

            out["audit"].push_back(std::move(row));
        }
        sqlite3_finalize(st);
        setJson(res, out);
    });

    svr.Post("/api/audit/verify", [&](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        if (!checkAuth(req, app.cfg.admin.adminToken)) { setJson(res, {{"error","unauthorized"}}, 401); return; }

        std::lock_guard<std::mutex> lk(app.m);
        const auto auditKey = app.keyManager.deriveAuditHmacKey();
        access_storage::SqliteAuditLog::Hash32 h{};
        std::copy(auditKey.begin(), auditKey.end(), h.begin());

        auto vr = access_storage::verifyAuditChain(app.store->dbHandle(), h);
        setJson(res, {{"ok", vr.ok}, {"error", vr.error}});
    });

    // ---- DB export/import ----
    svr.Get("/api/db/export", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { res.status = 401; res.set_content("unauthorized", "text/plain"); return; }

        std::ifstream f(app.dbPath, std::ios::binary);
        if (!f) { res.status = 500; res.set_content("cannot open db file", "text/plain"); return; }
        std::ostringstream ss; ss << f.rdbuf();

        res.set_header("Content-Disposition", "attachment; filename=\"access.db\"");
        res.set_content(ss.str(), "application/octet-stream");
    });

    svr.Post("/api/db/import", [&](const httplib::Request& req, httplib::Response& res) {
        if (!checkAuth(req, app.cfg.admin.adminToken)) { res.status = 401; res.set_content("unauthorized", "text/plain"); return; }

        if (!req.is_multipart_form_data() || !req.form.has_file("db")) {
            res.status = 400;
            res.set_content("expected multipart form-data with file field 'db'", "text/plain");
            return;
        }
        const auto file = req.form.get_file("db");
        if (file.content.size() > app.cfg.admin.maxUploadBytes) {
            res.status = 413;
            res.set_content("file too large", "text/plain");
            return;
        }

        const std::string tmp = app.dbPath + ".upload.tmp";
        { std::ofstream out(tmp, std::ios::binary); out.write(file.content.data(), (std::streamsize)file.content.size()); }

        std::string error;
        const bool ok = app.importDbFile(tmp, error);

        std::error_code ec;
        std::filesystem::remove(tmp, ec);

        if (!ok) {
            res.status = 400;
            res.set_content("IMPORT FAILED: " + error, "text/plain");
            return;
        }
        res.set_content("IMPORT OK (integrity + verify passed, DB swapped, reopened)", "text/plain");
    });

    // ---- access/check (optional) ----
    svr.Post("/api/access/check", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            const std::string frameHex = j.at("frame_hex").get<std::string>();
            auto bytes = hexToBytes(frameHex);

            std::lock_guard<std::mutex> lk(app.m);
            auto r = app.engine->handleFrameBytes(bytes, app.replayByReader);
            setJson(res, {{"allow", r.allow}, {"reason", r.reason}});
        } catch (const std::exception& e) {
            setJson(res, {{"error", e.what()}}, 400);
        }
    });
}

void registerAllRoutes(httplib::Server& svr, AppState& app) {
    registerRoutes(svr, app);
}

} // namespace admin
