// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once

#include <vector>
#include <string>

namespace fishnets
{
struct WebSocketClientSSLSettings
{
    // additional custom certificates to support
    std::vector<std::string> customCertificates;

    // enable certificate support from the host OS
    // NOT YET SUPPORTED
    bool enableNativeCertificateSupport = false;
};
}
