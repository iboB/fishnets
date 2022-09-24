// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "TestSSLSettings.hpp"

#include <fishnets/WebSocketClientSSLSettings.hpp>
#include <fishnets/WebSocketServerSSLSettings.hpp>

#include "../example/RootCertificates.inl"
#include "../example/ServerCertificate.inl"

const std::unique_ptr<fishnets::WebSocketClientSSLSettings> testClientSSLSettings;
const std::unique_ptr<fishnets::WebSocketServerSSLSettings> testServerSSLSettings;
