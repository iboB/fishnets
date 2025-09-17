// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
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
    struct HeaderFields {
        std::string userAgent;
        std::string contentType;
        std::string accept;
        bool keepAlive = false; // note that false here means omitting the header field
    };
    HeaderFields fields;

    // constructors are intentionally implicit
    HttpRequestDesc(
        std::string method,
        Scheme scheme,
        std::string host,
        std::string target,
        HeaderFields fields = {}
    );
    HttpRequestDesc(
        std::string method,
        Scheme scheme,
        std::string host,
        uint16_t port,
        std::string target,
        HeaderFields fields = {}
    );
    HttpRequestDesc(std::string method, std::string_view url, HeaderFields fields = {});
    HttpRequestDesc(std::string_view request, HeaderFields fields = {});
};

} // namespace fishnets
