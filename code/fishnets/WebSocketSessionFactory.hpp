// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once

#include "WebSocketSessionPtr.hpp"

#include <functional>

namespace fishnets
{
struct WebSocketEndpointInfo;
using WebSocketSessionFactoryFunc = std::function<WebSocketSessionPtr(const WebSocketEndpointInfo&)>;
}
