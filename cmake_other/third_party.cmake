include(FetchContent)

set(SODIUM_INSTALL_DIR "${CMAKE_SOURCE_DIR}/third_party/sodium")
FetchContent_Declare(sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG        e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
  SOURCE_DIR     "${CMAKE_SOURCE_DIR}/third_party/sodium"
)
FetchContent_MakeAvailable(sodium)

set(GTEST_INSTALL_DIR "${CMAKE_SOURCE_DIR}/third_party/googletest")
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
  SOURCE_DIR     "${CMAKE_SOURCE_DIR}/third_party/googletest"
)
FetchContent_MakeAvailable(googletest)

set(NLOHMAN_INSTALL_DIR "${CMAKE_SOURCE_DIR}/third_party/nlohmann")
FetchContent_Declare(nlohmann
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.11.3
  SOURCE_DIR     "${CMAKE_SOURCE_DIR}/third_party/nlohmann"
)
FetchContent_MakeAvailable(nlohmann)

set(YAML_CPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/third_party/yaml-cpp")
FetchContent_Declare(yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG        yaml-cpp-0.9.0
  SOURCE_DIR     "${CMAKE_SOURCE_DIR}/third_party/yaml-cpp"
)
FetchContent_MakeAvailable(yaml-cpp)

set(HTTPLIB_INSTALL_DIR "${CMAKE_SOURCE_DIR}/third_party/cpp-httplib")
FetchContent_Declare(cpp_httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG        v0.30.1
  SOURCE_DIR     "${HTTPLIB_INSTALL_DIR}"
)
FetchContent_MakeAvailable(cpp_httplib)

# There are some strange bugs with cpp-httplib when it's built as a static library, so we will just use it as header-only. 
if (NOT TARGET cpp_httplib)
  add_library(cpp_httplib INTERFACE)
  target_include_directories(cpp_httplib INTERFACE "${HTTPLIB_INSTALL_DIR}")
endif()