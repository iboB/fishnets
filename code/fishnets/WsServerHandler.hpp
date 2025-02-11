// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "WsConnectionHandlerPtr.hpp"
#include <functional>
#include <string>

namespace fishnets {

class Context;
struct EndpointInfo;

namespace impl {
class WsServer;
}

class FISHNETS_API WsServerHandler {
public:
    virtual ~WsServerHandler();

    virtual WsConnectionHandlerPtr onAccept(const EndpointInfo& ep) = 0;

    // the default implementation logs to stderr
    virtual void onError(std::string msg);

    // valid on any thread
    void stop();
private:
    friend class Context;
    friend class impl::WsServer;
    std::weak_ptr<impl::WsServer> m_server;
};

class SimpleServerHandler : public WsServerHandler {
public:
    using ConnectionHandlerFactory = std::function<WsConnectionHandlerPtr(const EndpointInfo&)>;
    ConnectionHandlerFactory factory;

    SimpleServerHandler(ConnectionHandlerFactory f) : factory(std::move(f)) {}

    virtual WsConnectionHandlerPtr onAccept(const EndpointInfo& ep) override {
        return factory(ep);
    }
};
} // namespace fishnets
