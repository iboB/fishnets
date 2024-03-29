# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
icm_add_lib(fishnets FISHNETS
    FishnetsImpl.cpp
)
add_library(fishnets::fishnets ALIAS fishnets)

icm_bigobj(FishnetsImpl.cpp)

target_link_libraries(fishnets
    PRIVATE
        Boost::beast
        ${CMAKE_THREAD_LIBS_INIT}
    PUBLIC
        splat::splat
        itlib::itlib
)

if(FISHNETS_SSL)
    target_link_libraries(fishnets PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    target_compile_definitions(fishnets PRIVATE -DFISHNETS_ENABLE_SSL=1)
else()
    target_compile_definitions(fishnets PRIVATE -DFISHNETS_ENABLE_SSL=0)
endif()

target_include_directories(fishnets INTERFACE ..)
