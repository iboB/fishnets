// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>

namespace fishnets {
class HttpResponseHandler;
using HttpResponseHandlerPtr = std::shared_ptr<HttpResponseHandler>;
} // namespace fishnets
