add_executable( engine_test engine_test.cpp 
                engine_rotation_test.cpp)

target_link_libraries(engine_test PRIVATE   access_decision 
                                            access_storage 
                                            key_manager 
                                            GTest::gtest_main 
                                            sodium)


add_test(NAME engine_test COMMAND engine_test)