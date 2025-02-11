// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "EndpointInfo.hpp"
#include "WsServerHandlerPtr.hpp"
#include "WsConnectionHandlerPtr.hpp"
#include "ExecutorPtr.hpp"

namespace fishnets {

class SslContext;
class ContextWorkGuard;

class FISHNETS_API Context {
public:
    Context();
    ~Context();

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    // block the current thread until the context is stopped
    void run();

    // force stop the context (disregarding pending work, including work guards)
    void stop();

    bool stopped() const;

    void restart();

    ContextWorkGuard makeWorkGuard();

    ExecutorPtr makeExecutor();

    void wsServe(
        const EndpointInfo& endpoint,
        WsServerHandlerPtr handler,
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
