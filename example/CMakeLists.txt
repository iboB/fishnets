add_executable(echo-server e-EchoServer.cpp)
target_link_libraries(echo-server fishnets)

add_executable(oneshot-client e-OneshotClient.cpp)
target_link_libraries(oneshot-client fishnets)
