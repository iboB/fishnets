icm_add_lib(fishnets FISHNETS
    FishnetsImpl.cpp
)

icm_bigobj(FishnetsImpl.cpp)

target_link_libraries(fishnets
    PRIVATE
        Boost::beast
        ${CMAKE_THREAD_LIBS_INIT}
    PUBLIC
        splat
        itlib
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
