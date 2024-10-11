# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(fishnets)

# cpm
include(./get_cpm.cmake)

#######################################
# cmake lib
CPMAddPackage(gh:iboB/icm@1.5.1)

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
option(FISHNETS_SSL "fisnets: add ssl and secure websocket support" ON)

if(ICM_DEV_MODE)
    mark_as_advanced(FISHNETS_BUILD_TESTS FISHNETS_BUILD_EXAMPLES)
endif()

#######################################
# packages
CPMAddPackage(gh:iboB/splat@1.3.3)
CPMAddPackage(gh:iboB/itlib@1.11.4)

find_package(Threads REQUIRED)
if(FISHNETS_SSL)
    find_package(OpenSSL REQUIRED)
endif()

if(NOT TARGET Boost::boost)
    # only add boost if not added from the outside
    CPMAddPackage(gh:iboB/boost-trim@1.85.0)
endif()

if(NOT TARGET Boost::beast)
    # beast is header only, so this is fine
    add_library(Boost::beast ALIAS Boost::boost)
endif()

#######################################
# subdirs

add_subdirectory(code/fishnets)

if(FISHNETS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(FISHNETS_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

if(ICM_DEV_MODE)
    # only add scratch project in dev mode
    add_subdirectory(scratch)
endif()
