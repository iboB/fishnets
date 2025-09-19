// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "HttpRequestDesc.hpp"
#include "HttpMsgBody.hpp"
#include "HttpRequestOptions.hpp"
#include <itlib/expected.hpp>
#include <itlib/ufunction.hpp>

namespace xeq { class context; }

namespace fishnets {

class SslContext;

using SimpleHttpRequestCb = itlib::ufunction<void(itlib::expected<std::string, std::string>)>;

FISHNETS_API void makeSimpleHttpRequest(
    xeq::context& ctx,
    const HttpRequestDesc& desc,
    ConstHttpMsgBody body,
    SimpleHttpRequestCb cb,
    HttpRequestOptions opts = {},
    SslContext* sslCtx = nullptr
);

} // namespace fishnets
