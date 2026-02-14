add_library(protocol_lib 
    src/packet.cpp
    src/protocol_utils.cpp
    src/frame.cpp
    src/frame_parser.cpp
    src/replay_window.cpp
)

target_include_directories(protocol_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (TESTING_MODE) 
    add_subdirectory(tests)
endif()