// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "WsServerSessionHandlerFactory.hpp"
#include "WsClientSessionHandlerFactory.hpp"

namespace fishnets {

class FISHNETS_API Context {
public:
    Context();
    ~Context();

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    // block the current thread until the context is stopped
    void run();

    // stop the context
    void stop();

    // complete any pending tasks and then stop
    void completeAndStop();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace fishnets
