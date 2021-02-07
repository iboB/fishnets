// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once

#include <memory>

namespace fishnets
{
struct WebSocketClientSSLSettings;
struct WebSocketServerSSLSettings;
}

extern const std::unique_ptr<fishnets::WebSocketClientSSLSettings> testClientSSLSettings;
extern const std::unique_ptr<fishnets::WebSocketServerSSLSettings> testServerSSLSettings;
