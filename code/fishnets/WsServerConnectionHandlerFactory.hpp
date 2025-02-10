// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "WsConnectionHandlerPtr.hpp"
#include <functional>

namespace fishnets {
struct EndpointInfo;
using WsServerConnectionHandlerFactory = std::function<WsConnectionHandlerPtr(const EndpointInfo&)>;
} // namespace fishnets
