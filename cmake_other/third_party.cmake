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