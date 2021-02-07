icm_add_lib(fishnets FISHNETS
    FishnetsImpl.cpp
)

icm_bigobj(FishnetsImpl.cpp)

target_link_libraries(fishnets
    PRIVATE
        boost-beast
        OpenSSL::SSL
        OpenSSL::Crypto
        ${CMAKE_THREAD_LIBS_INIT}
    PUBLIC
        splat
        itlib
)

target_include_directories(fishnets INTERFACE ..)
