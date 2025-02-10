// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsConnectionHandler.hpp"
#include "WebSocketOptions.hpp"

namespace fishnets {

WsConnectionHandler::~WsConnectionHandler() = default;
WebSocketOptions WsConnectionHandler::getInitialOptions() {
    return {};
};

} // namespace fishnets
