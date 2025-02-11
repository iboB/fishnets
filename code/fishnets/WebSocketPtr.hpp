// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <memory>

namespace fishnets {
class WebSocket;
using WebSocketPtr = std::unique_ptr<WebSocket>;
} // namespace fishnets
