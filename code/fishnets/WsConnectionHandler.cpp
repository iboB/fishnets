// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsConnectionHandler.hpp"
#include "WebSocketOptions.hpp"
#include <iostream>

namespace fishnets {

WsConnectionHandler::~WsConnectionHandler() = default;

void WsConnectionHandler::onConnectionError(std::string message) {
    std::cerr << "WebSocket connection error: " << message << std::endl;
}

WebSocketOptions WsConnectionHandler::getInitialOptions() {
    return {};
};

} // namespace fishnets
