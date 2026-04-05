cmake_minimum_required(VERSION 3.20)
project(access_security)

set(TESTING_MODE ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SODIUM_DISABLE_TESTS ON)

if(TESTING_MODE)
    enable_testing()
endif()

include(${CMAKE_SOURCE_DIR}/cmake_other/third_party.cmake)

add_subdirectory(crypto_lib)
add_subdirectory(protocol_lib)
add_subdirectory(key_manager)
add_subdirectory(access_core)
add_subdirectory(access_decision)
add_subdirectory(access_storage)
add_subdirectory(config_loader)
add_subdirectory(runtime_events)
add_subdirectory(access_admin)
add_subdirectory(experiments)