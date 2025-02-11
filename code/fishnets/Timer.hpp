// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "ExecutorPtr.hpp"
#include "TimerCb.hpp"
#include <chrono>
#include <cstdint>
#include <memory>

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

    using Cb = itlib::ufunction<void(bool cancelled)>;
    virtual void addCallback(Cb cb) = 0;

    TimerPtr create(const ExecutorPtr& ex);
private:
    // sealed interface
    Timer();
    friend struct TimerImpl;
};

} // namespace fishnets
