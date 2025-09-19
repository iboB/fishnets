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
    bool keepAlive = false; // note that false here means omitting the header field
};

} // namespace fishnets
