// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <itlib/opt_ref_buffer.hpp>
#include <cstdint>

namespace fishnets {
using HttpMsgBody = itlib::opt_ref_buffer;
using ConstHttpMsgBody = itlib::const_opt_ref_buffer;
} // namespace fishnets
