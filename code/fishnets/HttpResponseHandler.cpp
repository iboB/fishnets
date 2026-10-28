// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "HttpResponseHandler.hpp"
#include <cstdio>

namespace fishnets {

HttpResponseHandler::~HttpResponseHandler() = default;

void HttpResponseHandler::onError(std::string message) {
    fprintf(stderr, "HTTP request error: %s\n", message.c_str());
}

} // namespace fishnets
