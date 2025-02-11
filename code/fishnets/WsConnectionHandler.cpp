// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsConnectionHandler.hpp"
#include "WebSocketOptions.hpp"
#include <cstdio>

namespace fishnets {

WsConnectionHandler::~WsConnectionHandler() = default;

void WsConnectionHandler::onConnectionError(std::string message) {
    fprintf(stderr, "WebSocket connection error: %s\n", message.c_str());
}

WebSocketOptions WsConnectionHandler::getInitialOptions() {
    return {};
};

} // namespace fishnets
