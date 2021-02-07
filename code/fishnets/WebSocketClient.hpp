// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once
#include "API.h"

#include "WebSocketSessionPtr.hpp"

#include <cstdint>
#include <string>

namespace fishnets
{

class FISHNETS_API WebSocketClient
{
public:
    WebSocketClient(WebSocketSessionPtr session, const std::string& addr, uint16_t port, bool https = false);
};

}
