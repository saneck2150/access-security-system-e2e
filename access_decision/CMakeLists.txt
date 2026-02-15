add_library(access_decision
  src/payload.cpp
  src/policy.cpp
  src/engine.cpp
  src/card_id_hasher.cpp
)

target_include_directories(access_decision PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(access_decision PUBLIC
  access_core
  crypto_lib
  protocol_lib
  key_manager
  nlohmann_json::nlohmann_json
)

if (TESTING_MODE)
  add_subdirectory(tests)
endif()
