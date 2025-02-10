// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>

namespace fishnets {
class WsConnectionHandler;
using WsConnectionHandlerPtr = std::shared_ptr<WsConnectionHandler>;
} // namespace fishnets
