// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#include "TestSSLSettings.hpp"

#include <fishnets/WebSocketClientSSLSettings.hpp>
#include <fishnets/WebSocketServerSSLSettings.hpp>

#include "../example/RootCertificates.inl"
#include "../example/ServerCertificate.inl"

const std::unique_ptr<fishnets::WebSocketClientSSLSettings> testClientSSLSettings;
const std::unique_ptr<fishnets::WebSocketServerSSLSettings> testServerSSLSettings;
