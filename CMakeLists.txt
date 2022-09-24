# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(fishnets)

# cpm
include(./get_cpm.cmake)

#######################################
# cmake lib
CPMAddPackage(gh:iboB/icm@1.3.4)

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
CPMAddPackage(gh:iboB/splat@1.2.1)
CPMAddPackage(gh:iboB/itlib@1.6.3)

find_package(Threads REQUIRED)
if(FISHNETS_SSL)
    if (WIN32)
        set(OPENSSL_ROOT_DIR C:/tools/OpenSSL-Win64)
    endif()
    find_package(OpenSSL REQUIRED)
endif()

if(ICM_DEV_MODE)
    # only add boost in dev mode
    # otherwise rely on the external project providing it
    CPMAddPackage(gh:iboB/boost-trim@1.79.0)
    add_library(Boost::beast ALIAS Boost::boost)

    # only add scratch project in dev mode
    add_subdirectory(scratch)
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
