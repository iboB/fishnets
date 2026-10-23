// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "EndpointInfo.hpp"
#include <itlib/ufunction.hpp>
#include <itlib/expected.hpp>
#include <vector>

namespace xeq { class context; }

namespace fishnets {

using ResolveResult = itlib::expected<std::vector<EndpointInfo>, std::string>;
using ResolveCb = itlib::ufunction<void(ResolveResult)>;

FISHNETS_API void resolve(
    xeq::context& ctx,
    std::string_view host,
    std::string_view service,
    ResolveCb cb
);

inline void resolve(
    xeq::context& ctx,
    std::string_view host,
    uint16_t port,
    ResolveCb cb
) {
    auto portStr = std::to_string(port);
    resolve(ctx, host, portStr, std::move(cb));
}

FISHNETS_API void resolve(
    xeq::context& ctx,
    std::string_view url,
    ResolveCb cb
);

} // namespace fishnets
