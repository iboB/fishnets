// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <itlib/opt_ref_buffer.hpp>
#include <cstdint>

namespace fishnets {
using HttpMsgBody = itlib::opt_ref_buffer_t<uint8_t>;
using ConstHttpMsgBody = itlib::opt_ref_buffer_t<const uint8_t>;
} // namespace fishnets
