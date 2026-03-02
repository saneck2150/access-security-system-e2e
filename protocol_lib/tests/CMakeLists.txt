add_executable(protocol_lib_test
  packet_test.cpp
  frame_test.cpp
  replay_window_test.cpp
)

target_link_libraries(protocol_lib_test
  PRIVATE
    protocol_lib
    GTest::gtest_main
)

add_test(NAME protocol_lib_test COMMAND protocol_lib_test)