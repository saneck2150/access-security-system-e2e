add_library(access_storage
  src/sqlite_access_store.cpp
)

target_include_directories(access_storage PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(SQLite3 REQUIRED)

if (TESTING_MODE) 
    add_subdirectory(tests)
endif()

target_link_libraries(access_storage PUBLIC SQLite::SQLite3 access_decision)
