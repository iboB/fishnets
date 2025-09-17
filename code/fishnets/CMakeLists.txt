# Copyright (c) Borislav Stanimirov
# SPDX-License-Identifier: MIT
#
icm_add_lib(fishnets FISHNETS
    AsioImpl.cpp

    WsConnectionHandler.cpp

    HttpRequestHeader.cpp
    HttpResponseHandler.cpp

    util/WsSessionHandler.cpp
)
add_library(fishnets::fishnets ALIAS fishnets)

target_compile_features(fishnets PUBLIC cxx_std_20)

icm_bigobj(AsioImpl.cpp)

target_link_libraries(fishnets
    PRIVATE
        furi::furi
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
