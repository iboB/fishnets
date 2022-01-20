// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once

#include <string>

namespace fishnets
{
struct WebSocketServerSSLSettings
{
    // strings or files in pem format

    std::string certificate;
    std::string certificateFile; // only if certificate is empty

    std::string privateKey;
    std::string privateKeyFile; // only if private key is empty

    std::string tmpDH;
    std::string tmpDHFile;  // only if private key is empty
};
}
