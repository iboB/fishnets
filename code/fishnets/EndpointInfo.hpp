// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <cstdint>
#include <string>

namespace fishnets {
struct EndpointInfo {
    std::string address;
    uint16_t port = 0;
};

// utility constants suitable for servers
// they mean the the server accepts connections on any address from the space
inline constexpr auto IPv4 = "ipv4";
inline constexpr auto IPv6 = "ipv6";

} // namespace fishnets
