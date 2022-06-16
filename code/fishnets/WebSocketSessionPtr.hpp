// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
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
