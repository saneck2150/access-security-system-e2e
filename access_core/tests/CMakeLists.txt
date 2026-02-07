add_executable(handle_frame_test handle_frame_test.cpp)

target_link_libraries(handle_frame_test PRIVATE 
    access_core
    sodium 
    GTest::gtest_main)

add_test(NAME handle_frame_test COMMAND handle_frame_test)