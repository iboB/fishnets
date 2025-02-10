// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <memory>

namespace fishnets {
class WsSessionHandler;
using WsSessionHandlerPtr = std::shared_ptr<WsSessionHandler>;

// this is not really needed here per se,
// but it's useful if you just want to forward declare session factories
struct EndpointInfo;
} // namespace fishnets
