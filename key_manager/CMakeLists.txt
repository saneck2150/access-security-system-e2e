add_library(key_manager
  src/key_manager.cpp
  src/hex_utils.cpp
)

target_include_directories(key_manager PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(key_manager PUBLIC
  crypto_lib
)