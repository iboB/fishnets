// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "WsConnectionHandlerPtr.hpp"
#include <memory>

namespace fishnets {

struct EndpointInfo;

class FISHNETS_API WsServerConnection {
public:
    virtual const EndpointInfo& localEndpointInfo() const noexcept = 0;
    virtual EndpointInfo getRemoteEndpointInfo() const noexcept = 0;

    // call to accept the connection with the provided handler
    // valid on any thread
    // a nullptr handler is equivalent to actively rejecting the connection
    virtual void accept(WsConnectionHandlerPtr handler) = 0;

    // call to actively reject the connection
    virtual void reject() = 0;

    // destroying the connection object without actively accepting or rejecting the connection
    // is equivalent to rejecting the connection (passive)
    virtual ~WsServerConnection();

private:
    // sealed interface
    WsServerConnection();
    friend class WsServerConnectionImpl;
};

using WsServerConnectionPtr = std::unique_ptr<WsServerConnection>;

} // namespace fishnets
