cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(fishnets)

# cpm
include(./get_cpm.cmake)

#######################################
# cmake lib
CPMAddPackage(
    NAME icm
    GITHUB_REPOSITORY iboB/icm
    VERSION 1.3.0
)
set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${icm_SOURCE_DIR}
)

include(icm_dev_mode)
include(icm_add_lib)
include(icm_bigobj)

#######################################
# options

option(FISHNETS_STATIC "fishnets: build as static lib" OFF)
option(FISHNETS_BUILD_TESTS "fishnets: build tests" ${ICM_DEV_MODE})
option(FISHNETS_BUILD_EXAMPLES "fishnets: build examples" ${ICM_DEV_MODE})

if(ICM_DEV_MODE)
    mark_as_advanced(FISHNETS_BUILD_TESTS FISHNETS_BUILD_EXAMPLES)
endif()

#######################################
# packages
CPMAddPackage(
    NAME splat
    GITHUB_REPOSITORY iboB/splat
    VERSION 1.0.0
)
CPMAddPackage(
    NAME itlib
    GITHUB_REPOSITORY iboB/itlib
    VERSION 1.2.2
)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

if(ICM_DEV_MODE)
    add_subdirectory(boost)
endif()

#######################################
# subdirs

add_subdirectory(code/fishnets)

if(FISHNETS_BUILD_TESTS)
    # enable_testing()
    # add_subdirectory(test)
endif()

if(FISHNETS_BUILD_EXAMPLES)
    # add_subdirectory(example)
endif()
