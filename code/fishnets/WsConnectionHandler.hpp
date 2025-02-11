// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "WebSocketPtr.hpp"
#include <memory>
#include <string>
#include <string_view>

namespace fishnets {

struct WebSocketOptions;

class FISHNETS_API WsConnectionHandler {
public:
    // doesn't need to be virtual since it's always handled through shared_ptr
    // but it helps us export the vtable
    virtual ~WsConnectionHandler();

    virtual void onConnected(WebSocketPtr ws, std::string_view target) = 0;

    // the default implementation logs to std::cerr
    virtual void onConnectionError(std::string message);

    // default implementation returns default options
    virtual WebSocketOptions getInitialOptions();
};

} // namespace fishnets
