// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "WsServerConnectionHandlerFactory.hpp"
#include "EndpointInfo.hpp"

namespace fishnets {

class SslContext;
class WsServerHandler;
class ContextWorkGuard;

class FISHNETS_API Context {
public:
    Context();
    ~Context();

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    // block the current thread until the context is stopped
    void run();

    // force stop the context (diregarding pending work, including work guards)
    void stop();

    bool stopped() const;

    void restart();

    ContextWorkGuard makeWorkGuard();

    void wsServe(
        const EndpointInfo& endpoint,
        WsServerConnectionHandlerFactory factory,
        SslContext* sslCtx = nullptr
    );

    void wsConnect(
        WsConnectionHandlerPtr handler,
        const EndpointInfo& endpoint,
        std::string_view target = "/",
        SslContext* sslCtx = nullptr
    );
    void wsConnect(
        WsConnectionHandlerPtr handler,
        std::string_view url,
        SslContext* sslCtx = nullptr
    );

    struct Impl; // opaque implementation
    Impl& impl() { return *m_impl; }
private:
    std::unique_ptr<Impl> m_impl;
};

} // namespace fishnets
