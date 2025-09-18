// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <itlib/opt_ref_buffer.hpp>
#include <cstdint>

namespace fishnets {
using HttpRequestBody = itlib::opt_ref_buffer_t<uint8_t>;
using ConstHttpRequestBody = itlib::opt_ref_buffer_t<const uint8_t>;
} // namespace fishnets
