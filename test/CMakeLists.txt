# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
CPMAddPackage(gh:iboB/doctest-util@0.1.2)

if(fishnetsHaveSsl)
    add_library(fishnets-TestSslCtx STATIC TestSslCtx.cpp)
    target_link_libraries(fishnets-TestSslCtx PUBLIC fishnets::fishnets)
    macro(ssl_test test)
        add_doctest_lib_test(${test}-ssl fishnets t-${test}.cpp LIBRARIES fishnets-TestSslCtx)
    endmacro()
else()
    macro(ssl_test)
    endmacro()
endif()

add_library(fishnets-TestNullSslCtx STATIC TestNullSslCtx.cpp)
target_link_libraries(fishnets-TestNullSslCtx PUBLIC fishnets::fishnets)
macro(non_ssl_test test)
    add_doctest_lib_test(${test} fishnets t-${test}.cpp LIBRARIES fishnets-TestNullSslCtx)
endmacro()

macro(dual_test test)
    non_ssl_test(${test})
    ssl_test(${test})
endmacro()

dual_test(ws-SimpleClientServer)
ssl_test(websocket.org)

non_ssl_test(HttpRequestDesc)
