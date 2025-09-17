// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "EndpointInfo.hpp"
#include "WsServerHandlerPtr.hpp"
#include <span>

namespace fishnets {

class Context;
class SslContext;

FISHNETS_API void wsServe(
    Context& ctx,
    std::span<const EndpointInfo> endpoints,
    WsServerHandlerPtr handler,
    SslContext* sslCtx = nullptr
);
void wsServe(
    Context& ctx,
    const EndpointInfo& endpoint,
    WsServerHandlerPtr handler,
    SslContext* sslCtx = nullptr
) {
    wsServe(ctx, {&endpoint, 1}, std::move(handler), sslCtx);
}

// serve both ipv4 and ipv6 on localhost
FISHNETS_API void wsServeLocalhost(
    Context& ctx,
    uint16_t port,
    WsServerHandlerPtr handler,
    SslContext* sslCtx = nullptr
);

}
