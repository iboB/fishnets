// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "HttpHeaderFields.hpp"
#include <string>
#include <cstdint>
#include <string_view>

namespace fishnets {

struct FISHNETS_API HttpRequestDesc {
    std::string method;

    enum Scheme {
        Unknown_Scheme,
        HTTP,
        HTTPS
    };

    Scheme scheme = Unknown_Scheme;

    std::string host; // without scheme, but with port if not the default for the scheme

    std::string target;

    // the rest are optional
    HttpHeaderFields fields;

    // constructors are intentionally implicit
    HttpRequestDesc(
        std::string method,
        Scheme scheme,
        std::string host,
        std::string target,
        HttpHeaderFields fields = {}
    );
    HttpRequestDesc(
        std::string method,
        Scheme scheme,
        std::string host,
        uint16_t port,
        std::string target,
        HttpHeaderFields fields = {}
    );
    HttpRequestDesc(std::string method, std::string_view url, HttpHeaderFields fields = {});
    HttpRequestDesc(std::string_view request, HttpHeaderFields fields = {});
};

} // namespace fishnets
