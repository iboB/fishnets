// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "HttpRequestDesc.hpp"
#include "HttpRequestBody.hpp"
#include "HttpResponseHandlerPtr.hpp"

namespace fishnets {

class Context;
class SslContext;

FISHNETS_API void makeHttpRequest(
    const HttpRequestDesc& desc,
    ConstHttpRequestBody body,
    HttpResponseHandlerPtr handler,
    SslContext* sslCtx = nullptr
);

} // namespace fishnets
