include(icm_testing)

CPMAddPackage(gh:iboB/doctest-lib@2.4.8a)
CPMAddPackage(gh:iboB/xec@1.3.1)

add_library(TestSSLSettings STATIC TestSSLSettings.cpp)
target_link_libraries(TestSSLSettings PUBLIC fishnets)
add_library(TestNullSSLSettings STATIC TestNullSSLSettings.cpp)
target_link_libraries(TestNullSSLSettings PUBLIC fishnets)

macro(fishnets_dual_test test)
    icm_add_doctest_lib_test(${test}-ws fishnets ${ARGN} LIBRARIES xec TestNullSSLSettings)
    if(FISHNETS_SSL)
        icm_add_doctest_lib_test(${test}-ssl fishnets ${ARGN} LIBRARIES xec TestSSLSettings)
    endif()
endmacro()

fishnets_dual_test(SimpleClientServer t-SimpleClientServer.cpp)
fishnets_dual_test(ServerMainThread t-ServerMainThread.cpp)
fishnets_dual_test(PostAfterClose t-PostAfterClose.cpp)
fishnets_dual_test(ReconnectingClient t-ReconnectingClient.cpp)
fishnets_dual_test(WSSessionHeartbeat t-WSSessionHeartbeat.cpp)
