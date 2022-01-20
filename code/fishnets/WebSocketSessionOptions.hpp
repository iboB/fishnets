// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
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
};
} // namespace fishnets
