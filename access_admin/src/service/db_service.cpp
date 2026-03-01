#include <filesystem>
#include <fstream>
#include <sstream>

#include <access_admin/app_state.hpp>
#include <access_admin/service/db_service.hpp>

namespace admin::service {

DbExportResult exportDatabase(AppState& app) {
    std::ifstream f(app.dbPath, std::ios::binary);
    if (!f) {
        return {false, kHttpServerError, "cannot open db file", {}};
    }

    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string content = ss.str();

    DbExportResult result;
    result.ok = true;
    result.http_status = kHttpOk;
    result.data = std::vector<char>(content.begin(), content.end());

    return result;
}

ServiceResult importDatabase(AppState& app, const std::string& data) {
    if (data.size() > app.cfg.admin.maxUploadBytes) {
        return errorResult("file too large", kHttpPayloadTooLarge);
    }

    const std::string tmp = app.dbPath + ".upload.tmp";

    {
        std::ofstream out(tmp, std::ios::binary);
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
    }

    std::string error;
    const bool ok = app.importDbFile(tmp, error);

    std::error_code ec;
    std::filesystem::remove(tmp, ec);

    if (!ok) {
        return errorResult("IMPORT FAILED: " + error, kHttpBadRequest);
    }

    return okResult({{"message", "IMPORT OK (integrity + verify passed, DB swapped, reopened)"}});
}

}  // namespace admin::service
