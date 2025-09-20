// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>

namespace fishnets {
class WsConnectionHandler;
using WsConnectionHandlerPtr = std::shared_ptr<WsConnectionHandler>;

// this is not really needed here per se,
// but it's useful if you just want to forward declare connection handler factories
struct EndpointInfo;
} // namespace fishnets
