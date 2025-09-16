// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>

namespace fishnets {
class HttpRequestBuilder;
using HttpRequestBuilderPtr = std::shared_ptr<HttpRequestBuilder>;
} // namespace fishnets
