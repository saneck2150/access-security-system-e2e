add_library(access_core
  src/frame_decryptor.cpp
  src/handle_frame.cpp
)

target_include_directories(access_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(access_core PUBLIC
  crypto_lib
  protocol_lib
)

if (TESTING_MODE)
  add_subdirectory(tests)
endif()