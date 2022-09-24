// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
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
