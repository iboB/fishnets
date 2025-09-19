// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "HttpRequestDesc.hpp"
#include "HttpMsgBody.hpp"
#include "HttpResponseHandlerPtr.hpp"

namespace xeq { class context; }

namespace fishnets {

class SslContext;

FISHNETS_API void makeHttpRequest(
    xeq::context& ctx,
    const HttpRequestDesc& desc,
    ConstHttpMsgBody body,
    HttpResponseHandlerPtr handler,
    SslContext* sslCtx = nullptr
);

} // namespace fishnets
