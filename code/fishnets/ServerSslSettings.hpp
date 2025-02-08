// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <string>

namespace fishnets {
struct ServerSSLSettings {
    // strings or files in pem format

    std::string certificate;
    std::string certificateFile; // only if certificate is empty

    std::string privateKey;
    std::string privateKeyFile; // only if private key is empty

    std::string tmpDH;
    std::string tmpDHFile;  // only if private key is empty
};
} // namespace fishnets
