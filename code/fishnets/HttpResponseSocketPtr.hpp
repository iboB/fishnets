// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <memory>

namespace fishnets {
class HttpResponseSocket;
using HttpResponseSocketPtr = std::unique_ptr<HttpResponseSocket>;
} // namespace fishnets
