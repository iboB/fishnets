// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>

namespace fishnets {

class Context;

class FISHNETS_API ContextWorkGuard {
public:
    ContextWorkGuard();
    explicit ContextWorkGuard(Context&);
    ~ContextWorkGuard();

    ContextWorkGuard(ContextWorkGuard&&) noexcept;
    ContextWorkGuard& operator=(ContextWorkGuard&&) noexcept;

    explicit operator bool() const noexcept { return !!m_impl; }

    void reset();

private:
    friend class Context;
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace fishnets
