// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "WsConnectionHandlerPtr.hpp"
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

    // caled when a new connection
    // returning nullptr rejects the connection, otherwise the handler is used to handle the connection
    virtual WsConnectionHandlerPtr onAccept(const EndpointInfo& local, const EndpointInfo& remote) = 0;

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
    using ConnectionHandlerFactory
        = std::function<WsConnectionHandlerPtr(const EndpointInfo& local, const EndpointInfo& remote)>;
    ConnectionHandlerFactory factory;

    SimpleServerHandler(ConnectionHandlerFactory f) : factory(std::move(f)) {}

    virtual WsConnectionHandlerPtr onAccept(const EndpointInfo& local, const EndpointInfo& remote) override {
        return factory(local, remote);
    }
};
} // namespace fishnets
