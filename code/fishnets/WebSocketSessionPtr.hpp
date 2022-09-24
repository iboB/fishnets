// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once

#include <memory>

namespace fishnets
{
class WebSocketSession;
using WebSocketSessionPtr = std::shared_ptr<WebSocketSession>;

// this is not really needed here per se,
// but it's useful if you just want to forward declare session factories
struct WebSocketEndpointInfo;
}
