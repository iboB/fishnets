// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "EndpointInfo.hpp"
#include "WsConnectionHandlerPtr.hpp"
#include <span>
#include <string_view>

namespace xeq { class context; }

namespace fishnets {

class SslContext;

// try to connect to the provided endpoints in order, until a connection is established or the list is exhausted
FISHNETS_API void wsConnect(
    xeq::context& ctx,
    WsConnectionHandlerPtr handler,
    std::span<const EndpointInfo> endpoints,
    std::string_view target = "/",
    SslContext* sslCtx = nullptr
);

// try to connect to a single endpoint
inline void wsConnect(
    xeq::context& ctx,
    WsConnectionHandlerPtr handler,
    const EndpointInfo& endpoint,
    std::string_view target = "/",
    SslContext* sslCtx = nullptr
) {
    wsConnect(ctx, std::move(handler), {&endpoint, 1}, target, sslCtx);
}

// try to connect to a single endpoint provided as a url
FISHNETS_API void wsConnect(
    xeq::context& ctx,
    WsConnectionHandlerPtr handler,
    std::string_view url,
    SslContext* sslCtx = nullptr
);

} // namespace fishnets
