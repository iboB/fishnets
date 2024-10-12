# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
include(icm_testing)

CPMAddPackage(gh:iboB/doctest-util@0.1.2)
CPMAddPackage(gh:iboB/xec@1.5.2)

add_library(fishnets-TestSSLSettings STATIC TestSSLSettings.cpp)
target_link_libraries(fishnets-TestSSLSettings PUBLIC fishnets)
add_library(fishnets-TestNullSSLSettings STATIC TestNullSSLSettings.cpp)
target_link_libraries(fishnets-TestNullSSLSettings PUBLIC fishnets)

macro(fishnets_dual_test test)
    add_doctest_lib_test(${test}-ws fishnets ${ARGN} LIBRARIES xec::xec fishnets-TestNullSSLSettings)
    if(fishnetsHaveSsl)
        add_doctest_lib_test(${test}-ssl fishnets ${ARGN} LIBRARIES xec::xec fishnets-TestSSLSettings)
    endif()
endmacro()

fishnets_dual_test(SimpleClientServer t-SimpleClientServer.cpp)
fishnets_dual_test(ServerMainThread t-ServerMainThread.cpp)
fishnets_dual_test(PostAfterClose t-PostAfterClose.cpp)
fishnets_dual_test(ReconnectingClient t-ReconnectingClient.cpp)
fishnets_dual_test(WSSessionHeartbeat t-WSSessionHeartbeat.cpp)
