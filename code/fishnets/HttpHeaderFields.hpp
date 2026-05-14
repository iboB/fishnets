// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <string>

namespace fishnets {

struct HttpHeaderFields {
    std::string userAgent;
    std::string contentType;
    std::string accept;

    // note that false here means omitting the 'keep-alive' header field from the request
    bool keepAlive = false;
};

} // namespace fishnets
