add_library(access_admin_lib
  src/app_state.cpp
  src/routes_api.cpp
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
