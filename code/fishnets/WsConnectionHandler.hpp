// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>
#include <string>
#include <string_view>

namespace fishnets {

class WebSocket;

class FISHNETS_API WsConnectionHandler {
public:
    // doesn't need to be virtual since it's always handled through shared_ptr
    // but it helps us export the vtable
    virtual ~WsConnectionHandler();

    virtual void onConnected(WebSocket ws, std::string_view target) = 0;
    virtual void onConnectionError(std::string message) = 0;
};

} // namespace fishnets
