// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once

#include "WebSocketSessionPtr.hpp"

#include <functional>

namespace fishnets
{
struct WebSocketEndpointInfo;
using WebSocketSessionFactoryFunc = std::function<WebSocketSessionPtr(const WebSocketEndpointInfo&)>;
}
