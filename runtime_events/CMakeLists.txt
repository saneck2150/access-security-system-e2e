add_library(runtime_events
  src/event_bus.cpp
)
target_include_directories(runtime_events PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)