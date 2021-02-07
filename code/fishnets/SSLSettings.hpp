// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once

#include <string_view>

namespace fishnets
{
struct SSLSettings
{
    // all must be in pem format
    std::string_view certificate;
    std::string_view privateKey;
    std::string_view tmpDH;
};
}
