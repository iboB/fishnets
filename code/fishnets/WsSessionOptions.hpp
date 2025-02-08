// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once

#include <optional>
#include <string>
#include <chrono>
#include <cstddef>

namespace fishnets {
struct WsSessionOptions {
    // id/name of host
    // for servers this will be set as the "Server" HTTP header field
    // for clients this will be set as the "User-Agent" HTTP header field
    std::optional<std::string> hostId;

    // max size of incoming frame
    // frames larger than that will be ignored
    std::optional<size_t> maxIncomingMessageSize;

    // timeout after which to disconnect when the other side doesn't respond
    // note that this doesn't mean the time in which the other side hasn't communicated
    // "not responding" is based on pings which the library does internally
    std::optional<std::chrono::milliseconds> pongTimeout;
};
} // namespace fishnets
