// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <cstdint>

namespace fishnets {
struct WebSocketEndpointInfo {
    std::string address;
    uint16_t port = 0;
};
} // namespace fishnets
