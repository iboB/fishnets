// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <itlib/ufunction.hpp>
#include <cstdint>

namespace fishnets {
using TimerCb = itlib::ufunction<void(uint64_t id, bool cancelled)>;
} // namespace fishnets
