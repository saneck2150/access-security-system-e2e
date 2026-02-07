cmake_minimum_required(VERSION 3.20)
project(access_security)

set (TESTING_MODE ON)
set (ENABLE_DEMOS ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SODIUM_DISABLE_TESTS ON)

if (TESTING_MODE)
    enable_testing()
endif()

include(${CMAKE_SOURCE_DIR}/cmake_other/third_party.cmake)

add_subdirectory(crypto_lib)
add_subdirectory(protocol_lib)
add_subdirectory(access_core)
add_subdirectory(access_decision)
add_subdirectory(access_storage)
add_subdirectory(config_loader)

add_executable(access_security src/main.cpp)

target_link_libraries(access_security PRIVATE 
    sodium 
    crypto_lib 
    protocol_lib
    access_core
    access_storage
    access_decision
    config_loader
    nlohmann_json::nlohmann_json
    yaml-cpp
)

if (ENABLE_DEMOS)
add_executable(handle_frame_behaviour_demo examples/handle_frame_behaviour_demo.cpp)
target_link_libraries(handle_frame_behaviour_demo PRIVATE 
    config_loader
    sodium 
    crypto_lib 
    protocol_lib
)
endif()