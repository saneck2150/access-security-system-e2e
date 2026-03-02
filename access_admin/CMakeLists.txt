add_library(access_admin_lib
  src/app_state.cpp
  src/http_utils.cpp
  src/routes_api.cpp
  src/service/service_types.cpp
  src/service/events_service.cpp
  src/service/readers_service.cpp
  src/service/door_roles_service.cpp
  src/service/cards_service.cpp
  src/service/audit_service.cpp
  src/service/db_service.cpp
  src/service/access_service.cpp
  src/service/hw_service.cpp
)

target_include_directories(access_admin_lib PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(access_admin_lib PUBLIC
  cpp_httplib
  runtime_events
  config_loader
  access_storage
  access_decision
  access_core
  protocol_lib
  crypto_lib
  key_manager
  nlohmann_json::nlohmann_json
  yaml-cpp
)

target_compile_definitions(access_admin_lib PUBLIC
  CPPHTTPLIB_PAYLOAD_MAX_LENGTH=20000000
)

add_executable(access_admin src/main.cpp)

target_link_libraries(access_admin PRIVATE
  access_admin_lib
)
