// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <string>
#include <cstdint>
#include <string_view>

namespace fishnets {

struct HttpRequestHeader {
    enum Method {
        GET,
        HEAD,
        POST,
        PUT,
        DEL,
    };

    Method method = GET;

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

    // utils
    static FISHNETS_API HttpRequestHeader make(
        Method method,
        Scheme scheme,
        std::string host,
        uint16_t port,
        std::string target,
        HeaderFields fields = {}
    );
    static FISHNETS_API HttpRequestHeader make(Method method, std::string_view url, HeaderFields fields = {});

    static HttpRequestHeader get(std::string_view url, HeaderFields fields = {}) {
        return make(GET, url, std::move(fields));
    }
    static HttpRequestHeader head(std::string_view url, HeaderFields fields = {}) {
        return make(HEAD, url, std::move(fields));
    }
    static HttpRequestHeader post(std::string_view url, HeaderFields fields = {}) {
        return make(POST, url, std::move(fields));
    }
    static HttpRequestHeader put(std::string_view url, HeaderFields fields = {}) {
        return make(PUT, url, std::move(fields));
    }
    static HttpRequestHeader del(std::string_view url, HeaderFields fields = {}) {
        return make(DEL, url, std::move(fields));
    }
};

} // namespace fishnets
