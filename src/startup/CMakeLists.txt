add_library(startup
    src/secure_frame_session.cpp
)

target_include_directories(startup PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(startup PUBLIC 
    sodium 
    crypto_lib 
    protocol_lib
)