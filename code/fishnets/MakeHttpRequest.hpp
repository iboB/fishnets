// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "HttpRequestBody.hpp"
#include "HttpResponseHandlerPtr.hpp"

namespace fishnets {

class Context;
class SslContext;
struct HttpRequestHeader;

void makeHttpRequest(
    const HttpRequestHeader& header,
    HttpRequestBody body,
    HttpResponseHandlerPtr handler,
    SslContext* sslCtx = nullptr
);
//void makeHttpRequest(
//    const HttpRequestHeader& header,
//    HttpRequestBody body,
//);


} // namespace fishnets
