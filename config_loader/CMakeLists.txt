add_library(config_loader
  src/config.cpp
)

target_include_directories(config_loader PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(config_loader PUBLIC
  access_core
  key_manager
  yaml-cpp
)