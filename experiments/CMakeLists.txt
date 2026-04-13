add_library(experiments_common STATIC
    src/experiment_context.cpp
    src/frame_factory.cpp
    src/seeded_nonce_generator.cpp
    src/metrics_collector.cpp
    src/scenario_common.cpp
    src/scenario_runner.cpp
)

target_include_directories(experiments_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(experiments_common PUBLIC
    access_decision
    access_core
    access_storage
    crypto_lib
    protocol_lib
    key_manager
    runtime_events
    nlohmann_json::nlohmann_json
    cpp_httplib
)

function(add_scenario name)
    add_executable(${name} src/${name}.cpp)
    target_link_libraries(${name} PRIVATE experiments_common)
endfunction()

add_scenario(s1_replay)
add_scenario(s2_tamper)
add_scenario(s3_rng_fault)
add_scenario(s3_cross_reader)
add_scenario(s4_seq_reset)
add_scenario(s5_tag_probe)
add_scenario(s6_throughput)
add_scenario(s7_nonce_tamper)
