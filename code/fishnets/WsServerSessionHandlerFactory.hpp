// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "WsSessionHandlerPtr.hpp"
#include <functional>

namespace fishnets {
using WsServerSessionHandlerFactory = std::function<WsSessionHandlerPtr(const EndpointInfo&)>;
}
