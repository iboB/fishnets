// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "WsServerConnection.hpp"
#include <functional>
#include <string>

namespace fishnets {

struct EndpointInfo;

namespace impl {
class WsServer;
}

class FISHNETS_API WsServerHandler {
public:
    virtual ~WsServerHandler();

    // called when a new connection is attempted
    virtual void onAccept(WsServerConnectionPtr connection) = 0;

    // called on accept errors, non fatal
    // server continues serving and accepting new connections after this, but the failed connection will be closed
    // the default implementation logs to stderr
    virtual void onError(std::string msg);

    // valid on any thread
    // stop accepting new sessions
    // note that this doesn't affect existing accepted sessions
    // they will continue to run until they are manually closed or their associated executors are stopped
    void stop();
private:
    friend class impl::WsServer;
    std::weak_ptr<impl::WsServer> m_server;
};

class SimpleServerHandler : public WsServerHandler {
public:
    using AcceptFunc = std::function<void(WsServerConnectionPtr)>;
    AcceptFunc accept;

    SimpleServerHandler(AcceptFunc f) : accept(std::move(f)) {}

    virtual void onAccept(WsServerConnectionPtr connection) final override {
        accept(std::move(connection));
    }
};
} // namespace fishnets
