// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "WsServerConnectionHandlerFactory.hpp"
#include "EndpointInfo.hpp"

namespace fishnets {

struct ServerSslSettings;
struct ClientSslSettings;
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
        EndpointInfo endpoint,
        WsServerConnectionHandlerFactory factory,
        const ServerSslSettings* ssl = nullptr
    );
    void wsConnect(
        EndpointInfo endpoint,
        WsConnectionHandlerPtr handler,
        const ClientSslSettings* ssl = nullptr
    );

private:
    friend class ContextWorkGuard;
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace fishnets
