// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "TestSSLSettings.hpp"

#include <fishnets/WebSocketClientSSLSettings.hpp>
#include <fishnets/WebSocketServerSSLSettings.hpp>

#include "../example/RootCertificates.inl"
#include "../example/ServerCertificate.inl"

const std::unique_ptr<fishnets::WebSocketClientSSLSettings> testClientSSLSettings =
    std::make_unique<fishnets::WebSocketClientSSLSettings>(fishnets::WebSocketClientSSLSettings{
        rootCertificates,
        false
    });

const std::unique_ptr<fishnets::WebSocketServerSSLSettings> testServerSSLSettings =
    std::make_unique<fishnets::WebSocketServerSSLSettings>(fishnets::WebSocketServerSSLSettings{
        certificate,
        std::string(),
        privateKey,
        std::string(),
        tmpDh,
        std::string()
    });
