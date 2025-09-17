// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <span>
#include <cstdint>
#include <type_traits>

namespace fishnets {

namespace impl {
template <typename T>
using byte_for = std::conditional_t<std::is_const<T>::value, const uint8_t, uint8_t>;
}

template <typename T>
std::span<impl::byte_for<T>> as_byte_span(std::span<T> s) {
    return {reinterpret_cast<impl::byte_for<T>*>(s.data()), s.size_bytes()};
}

} // namespace fishnets
