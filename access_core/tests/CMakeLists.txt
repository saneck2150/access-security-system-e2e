add_executable(handle_frame_test handle_frame_test.cpp)

target_link_libraries(handle_frame_test PRIVATE
    access_core
    access_decision
    sodium
    GTest::gtest_main)

add_test(NAME handle_frame_test COMMAND handle_frame_test)

add_executable(anomaly_detector_test anomaly_detector_test.cpp)

target_link_libraries(anomaly_detector_test PRIVATE
    access_core
    sodium
    GTest::gtest_main)

add_test(NAME anomaly_detector_test COMMAND anomaly_detector_test)