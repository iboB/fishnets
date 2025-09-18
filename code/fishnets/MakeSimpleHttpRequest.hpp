// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "HttpRequestDesc.hpp"
#include "HttpRequestBody.hpp"
#include "HttpRequestOptions.hpp"
#include <itlib/expected.hpp>
#include <itlib/ufunction.hpp>

namespace fishnets {

class Context;
class SslContext;

using SimpleHttpRequestCb = itlib::ufunction<void(itlib::expected<std::string, std::string>)>;

FISHNETS_API void makeSimpleHttpRequest(
    Context& ctx,
    const HttpRequestDesc& desc,
    ConstHttpRequestBody body,
    SimpleHttpRequestCb cb,
    HttpRequestOptions opts = {},
    SslContext* sslCtx = nullptr
);

} // namespace fishnets
