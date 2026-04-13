#include <iostream>
#include <thread>

#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>
#include <config_loader/config.hpp>
#include <httplib.h>
#include <key_manager/key_manager.hpp>

namespace admin {
void registerAllRoutes(httplib::Server& svr, AppState& app);
}

int main(int argc, char** argv) {
    admin::sodiumInitOrThrow();

    const std::string cfgPath = (argc > 1) ? argv[1] : "config/access_security.yaml";
    auto cfg = config_loader::loadFromYaml(cfgPath);

    auto master = key_manager::loadMasterKeyHexFile(cfg.keyManagement.masterKeyPath);
    key_manager::KeyManager km(master,
        {.currentKeyVersion = cfg.keyManagement.currentKeyVersion,
            .allowPreviousKeyVersion = cfg.keyManagement.allowPreviousKeyVersion});

    admin::AppState app(cfg, cfg.storage.sqlitePath, std::move(km));
    app.openOrCreate();

    // --- Decision Service on separate port (handles /api/decision/frame) ---
    httplib::Server decisionSvr;
    decisionSvr.Post("/api/decision/frame",
        [&](const httplib::Request& req, httplib::Response& res) {
            if (req.body.empty()) {
                admin::setJson(res, {{"allow", false}, {"reason", "empty_frame"}}, 400);
                return;
            }
            try {
                std::span<const uint8_t> frameBytes(
                    reinterpret_cast<const uint8_t*>(req.body.data()), req.body.size());

                std::lock_guard<std::mutex> lk(app.engineMutex);
                auto result = app.engine->handleFrameBytes(frameBytes, app.replayByReader);

                nlohmann::json j;
                j["allow"] = result.allow;
                j["reason"] = result.reason;
                admin::setJson(res, j);
            } catch (const std::exception& e) {
                std::cerr << "[decision] exception: " << e.what() << "\n";
                admin::setJson(res, {{"allow", false}, {"reason", "internal_error"}}, 500);
            }
        });

    const uint16_t decisionPort = cfg.admin.port + 1;  // e.g. 8081
    std::thread decisionThread([&]() {
        std::cout << "Decision service: http://127.0.0.1:" << decisionPort << "\n";
        if (!decisionSvr.listen("127.0.0.1", decisionPort)) {
            std::cerr << "decision service listen failed\n";
        }
    });

    // --- Main server (admin UI, hw endpoint, etc.) ---
    httplib::Server svr;
    admin::registerAllRoutes(svr, app);

    std::cout << "Admin server: http://" << cfg.admin.bindHost << ":" << cfg.admin.port << "\n";
    if (!svr.listen(cfg.admin.bindHost, cfg.admin.port)) {
        std::cerr << "listen failed\n";
        decisionSvr.stop();
        decisionThread.join();
        return 2;
    }

    decisionSvr.stop();
    decisionThread.join();
    return 0;
}