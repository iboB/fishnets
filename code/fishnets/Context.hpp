// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "WsServerSessionHandlerFactory.hpp"
#include "WsClientSessionHandlerFactory.hpp"

namespace fishnets {

struct ServerSslSettings;
struct ClientSslSettings;

class FISHNETS_API Context {
public:
    Context();
    ~Context();

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    // block the current thread until the context is stopped
    void run();

    // stop the context
    void stop();

    // complete any pending tasks and then stop
    void completeAndStop();

    void wsServe(
        EndpointInfo endpoint,
        WsServerSessionHandlerFactory factory,
        const ServerSslSettings* ssl = nullptr
    );
    void wsConnect(
        EndpointInfo endpoint,
        WsClientSessionHandlerFactory factory,
        const ClientSslSettings* ssl = nullptr
    );

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace fishnets
