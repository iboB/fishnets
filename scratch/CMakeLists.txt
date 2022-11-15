add_executable(scratch scratch.cpp)
target_link_libraries(scratch fishnets ${CMAKE_THREAD_LIBS_INIT})

add_executable(scratch-raw scratch-raw.cpp)
target_link_libraries(scratch-raw Boost::beast ${CMAKE_THREAD_LIBS_INIT})
