# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
icm_add_lib(fishnets FISHNETS
    FishnetsImpl.cpp
    AsioImpl.cpp
)
add_library(fishnets::fishnets ALIAS fishnets)

icm_bigobj(FishnetsImpl.cpp)
icm_bigobj(AsioImpl.cpp)

target_link_libraries(fishnets
    PRIVATE
        Boost::beast
        ${CMAKE_THREAD_LIBS_INIT}
    PUBLIC
        splat::splat
        itlib::itlib
)

if(fishnetsHaveSsl)
    target_link_libraries(fishnets PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    target_compile_definitions(fishnets PRIVATE -DFISHNETS_ENABLE_SSL=1)
else()
    target_compile_definitions(fishnets PRIVATE -DFISHNETS_ENABLE_SSL=0)
endif()

target_include_directories(fishnets INTERFACE ..)
