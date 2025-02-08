// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "WsSessionHandlerPtr.hpp"
#include <itlib/ufunction.hpp>

namespace fishnets {
// client factory is ufunction as it's only called once per connect
// this capturing non-copyable objects is a potentianl need
using WsClientSessionHandlerFactory = itlib::ufunction<WsSessionHandlerPtr(const EndpointInfo&)>;
}
