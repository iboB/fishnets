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

    // called on accept errors for a given endpoint
    // this is a fatal error for the given endpoint (others will continue accepting until stop is called)
    // the default implementation logs to stderr
    virtual void onError(const EndpointInfo& local, std::string msg);

    // called when the server is stopped, either by calling stop() or stopping the associated executors
    // will be invoken on one of the server executors, but which one is not defined
    // the default implementation does nothing
    virtual void onStopped();

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
