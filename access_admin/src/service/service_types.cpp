#include <access_admin/service/service_types.hpp>

namespace admin::service {

ServiceResult errorResult(const std::string& message, int status) {
    return {false, status, {{"error", message}}};
}

ServiceResult okResult(const json& body) {
    return {true, kHttpOk, body};
}

}  // namespace admin::service
