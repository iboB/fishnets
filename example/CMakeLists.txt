macro(fishnets_example example)
    add_executable(${example} ${ARGN})
    target_link_libraries(${example} fishnets)
endmacro()

CPMAddPackage(gh:iboB/xec@1.5.2)

fishnets_example(echo-server e-EchoServer.cpp)
fishnets_example(oneshot-client e-OneshotClient.cpp)
fishnets_example(terminal-client e-TerminalClient.cpp)
target_link_libraries(terminal-client xec::xec)
