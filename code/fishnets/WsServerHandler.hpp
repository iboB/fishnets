// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>
#include <string>
#include <string_view>

namespace fishnets {

struct EndpointInfo;
class WebSocket;

class FISHNETS_API WsServerHandler {
public:
    virtual ~WsServerHandler();

    struct FISHNETS_API EstablishHandler {
        virtual ~EstablishHandler();
        virtual void onConnected(std::unique_ptr<WebSocket> ws, std::string_view target) = 0;
        virtual void onError(std::string message) = 0;
    };

    // called when a new connection is accepted
    // return a handler to accept the connection or nullptr to decline it
    virtual std::shared_ptr<EstablishHandler> onAccept(const EndpointInfo& ep) = 0;
};

} // namespace fishnets
