// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <optional>
#include <string>
#include <chrono>
#include <cstddef>

namespace fishnets {

struct HttpRequestOptions {
    // max number of redirects to follow automatically
    // set to 0 to disable redirects
    int maxRedirects = 5;

    // timeout for the entire for each individual request
    // this means each redirect (if any) will have this timeout
    std::optional<std::chrono::milliseconds> timeout;

    // set the no_delay option on the underlying socket
    bool disableNagle = false;

    std::optional<size_t> maxResponseSize; // in bytes, no limit by default
};

} // namespace fishnets
