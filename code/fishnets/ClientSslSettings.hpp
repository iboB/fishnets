// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <vector>
#include <string>

namespace fishnets {
struct ClientSslSettings {
    // additional custom certificates to support
    std::vector<std::string> customCertificates;

    // enable certificate support from the host OS
    // NOT YET SUPPORTED
    bool enableNativeCertificateSupport = false;
};
} // namespace fishnets
