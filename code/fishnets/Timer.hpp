// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "ExecutorPtr.hpp"
#include <chrono>
#include <cstdint>
#include <memory>
#include <system_error>

namespace fishnets {

class Timer;
using TimerPtr = std::unique_ptr<Timer>;

class FISHNETS_API Timer {
public:
    virtual ~Timer();

    Timer(const Timer&) = delete;
    Timer& operator=(const Timer&) = delete;

    virtual void expireAfter(std::chrono::milliseconds timeFromNow) = 0;

    // due to the async nature of the system, after cancelling some callbacks may still be called with cancelled = false
    virtual void cancel() = 0;
    virtual void cancelOne() = 0;

    using Cb = itlib::ufunction<void(const std::error_code& cancelled)>;
    virtual void addCallback(Cb cb) = 0;

    static TimerPtr create(const ExecutorPtr& ex);
private:
    // sealed interface
    Timer();
    friend struct TimerImpl;
};

} // namespace fishnets
