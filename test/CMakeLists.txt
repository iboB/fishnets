include(icm_testing)

CPMAddPackage(
    NAME doctest-lib
    GITHUB_REPOSITORY iboB/doctest-lib
    GIT_TAG 2.4.4
)

macro(fishnets_dual_test test)
    icm_add_doctest_lib_test(${test}-ws fishnets ${ARGN} TestNullSSLSettings.cpp)
    # icm_add_doctest_lib_test(${test}-ssl fishnets ${ARGN} TestSSLSettings.cpp)
endmacro()

fishnets_dual_test(SimpleClientServer t-SimpleClientServer.cpp)
