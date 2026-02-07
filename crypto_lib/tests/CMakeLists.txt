add_executable(crypto_lib_test 
  hkdf_test.cpp 
  aead_roundtrip_test.cpp
)

target_link_libraries(crypto_lib_test
  PRIVATE
    crypto_lib
    protocol_lib
    GTest::gtest_main
)

add_test(NAME crypto_lib_test COMMAND crypto_lib_test)