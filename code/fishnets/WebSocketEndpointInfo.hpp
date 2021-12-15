// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once

#include <string>
#include <cstdint>

namespace fishnets
{
struct WebSocketEndpointInfo
{
    std::string address;
    uint16_t port;
};

} // namespace fishnets