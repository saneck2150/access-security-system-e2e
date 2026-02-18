#include <access_admin/app_state.hpp>
#include <access_admin/http_utils.hpp>

#include <config_loader/config.hpp>
#include <key_manager/key_manager.hpp>
#include <httplib.h>

#include <iostream>

namespace admin {
void registerAllRoutes(httplib::Server& svr, AppState& app);
}

int main(int argc, char** argv) {
    admin::sodiumInitOrThrow();

    const std::string cfgPath = (argc > 1) ? argv[1] : "config/access_security.yaml";
    auto cfg = config_loader::loadFromYaml(cfgPath);

    auto master = key_manager::KeyManager::loadMasterKeyHexFile(cfg.keyManagement.masterKeyPath);
    key_manager::KeyManager km(master, {
        .currentKeyVersion = cfg.keyManagement.currentKeyVersion,
        .allowPreviousKeyVersion = cfg.keyManagement.allowPreviousKeyVersion
    });

    admin::AppState app(cfg, cfg.storage.sqlitePath, std::move(km));
    app.openOrCreate();

    httplib::Server svr;
    admin::registerAllRoutes(svr, app);

    std::cout << "Admin server: http://" << cfg.admin.bindHost << ":" << cfg.admin.port << "\n";
    if (!svr.listen(cfg.admin.bindHost, cfg.admin.port)) {
        std::cerr << "listen failed\n";
        return 2;
    }
    return 0;
}
