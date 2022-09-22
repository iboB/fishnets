add_executable(scratch scratch.cpp)
target_link_libraries(scratch fishnets)

add_executable(scratch-raw scratch-raw.cpp)
target_link_libraries(scratch-raw boost-beast)

