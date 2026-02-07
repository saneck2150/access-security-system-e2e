add_executable(engine_test engine_test.cpp)
target_link_libraries(engine_test PRIVATE access_decision GTest::gtest_main sodium)
add_test(NAME engine_test COMMAND engine_test)
