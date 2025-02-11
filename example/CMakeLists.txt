macro(fishnets_example example)
    add_executable(fishnets-${example} ${ARGN})
    target_link_libraries(fishnets-${example} fishnets::fishnets)
endmacro()

fishnets_example(echo-server e-EchoServer.cpp)
fishnets_example(oneshot-client e-OneshotClient.cpp)
fishnets_example(terminal-client e-TerminalClient.cpp)
