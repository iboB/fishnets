# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(fishnets
    VERSION 1.0.0
    LANGUAGES CXX
)

# cpm
include(./get_cpm.cmake)

#######################################
# cmake lib
CPMAddPackage(gh:iboB/icm@1.5.6)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${icm_SOURCE_DIR}
)

include(icm_dev_mode)
include(icm_add_lib)
include(icm_bigobj)
include(icm_option)

#######################################
# options

option(BUILD_SHARED_LIBS "fishnets: build shared libraries" ON)
option(FISHNETS_BUILD_TESTS "fishnets: build tests" ${ICM_DEV_MODE})
option(FISHNETS_BUILD_EXAMPLES "fishnets: build examples" ${ICM_DEV_MODE})
icm_auto_option(FISHNETS_SSL "fisnets: add ssl and secure websocket support" AUTO)

if(ICM_DEV_MODE)
    mark_as_advanced(FISHNETS_BUILD_TESTS FISHNETS_BUILD_EXAMPLES)
endif()

#######################################
# packages
CPMAddPackage(gh:iboB/splat@1.3.4)
CPMAddPackage("gh:iboB/itlib@1.11.7a#cba8b3b")

find_package(Threads REQUIRED)
set(fishnetsHaveSsl FALSE)
if(FISHNETS_SSL)
    find_package(OpenSSL ${FISHNETS_SSL_REQUIRED})
    set(fishnetsHaveSsl ${OpenSSL_FOUND})
endif()
if(fishnetsHaveSsl)
    message(STATUS "fishnets: building WITH SSL support")
else()
    message(STATUS "fishnets: building with NO SSL support")
endif()

if(NOT TARGET Boost::boost)
    CPMAddPackage(
        NAME Boost
        VERSION 1.87.0
        URL https://github.com/boostorg/boost/releases/download/boost-1.87.0/boost-1.87.0-cmake.tar.xz
        URL_HASH SHA256=7da75f171837577a52bbf217e17f8ea576c7c246e4594d617bfde7fafd408be5
        SYSTEM TRUE
        OPTIONS "BOOST_ENABLE_CMAKE ON"
                "BOOST_INCLUDE_LIBRARIES asio\\\;beast"
    )
endif()

if(NOT TARGET Boost::asio)
    add_library(Boost::asio ALIAS Boost::boost)
endif()

if(NOT TARGET Boost::beast)
    add_library(Boost::beast ALIAS Boost::boost)
endif()

CPMAddPackage(gh:iboB/furi@1.2.1)
CPMAddPackage("gh:iboB/xeq@0.0.2#2805bce")

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
