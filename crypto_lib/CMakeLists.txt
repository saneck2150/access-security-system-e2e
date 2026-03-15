add_library(crypto_lib
    src/hkdf.cpp
    src/secure_aead.cpp
    src/nonce_generator.cpp
    src/crypto_utils.cpp)

target_include_directories(crypto_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (TESTING_MODE) 
    add_subdirectory(tests)
endif()

target_link_libraries(crypto_lib PUBLIC sodium)