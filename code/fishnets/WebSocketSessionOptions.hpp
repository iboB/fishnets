// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <optional>
#include <chrono>
#include <cstddef>

namespace fishnets
{
struct WebSocketSessionOptions
{
    // id/name of host
    // for servers this will be set as the "Server" HTTP header field
    // for clients this will be set as the "User-Agent" HTTP header field
    std::optional<std::string> hostId;

    // max size of incoming message
    // messages larger than that will be ignored
    std::optional<size_t> maxIncomingMessageSize;

    // timeout after which to disconnect when the other side doesn't respond
    // note that this doesn't mean the time in which the other side hasn't communicated
    // "not respoding" is based on pings which the library does internally
    std::optional<std::chrono::milliseconds> idleTimeout;

    // interval for wsHeartBeat. 0 means never
    std::optional<std::chrono::milliseconds> heartbeatInterval;
};
} // namespace fishnets
