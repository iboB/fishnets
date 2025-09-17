// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "HttpResponseSocketPtr.hpp"
#include <memory>
#include <string>
#include <string_view>

namespace fishnets {
struct HttpRequestOptions;

class FISHNETS_API HttpResponseHandler {
public:
    virtual ~HttpResponseHandler();

    virtual void onReady(HttpResponseSocketPtr socket, std::string_view host, std::string_view target) = 0;

    // default implementation returns default options
    virtual HttpRequestOptions getOptions();

    // the default implementation logs to stderr
    virtual void onError(std::string message);
};
} // namespace fishnets
