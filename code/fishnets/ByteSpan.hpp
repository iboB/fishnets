// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <span>
#include <cstddef>

namespace fishnets {
using ByteSpan = std::span<std::byte>;
using ConstByteSpan = std::span<const std::byte>;
} // namespace fishnets
