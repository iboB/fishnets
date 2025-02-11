// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "ExecutorPtr.hpp"
#include "TimerCb.hpp"
#include <chrono>
#include <cstdint>

namespace fishnets {
// these functions are only valid on the executor itself

// post a task to be executed after a timeout
// the callback will be called with the id of the timer and whether it was cancelled
// the associated task will extend the lifetime of the handler until the callback is called
// starting a timer with a given id will cancel any previous timer with the same id
FISHNETS_API void Executor_startTimer(Executor& ex, uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb);

// due to the async nature of the system, after cancelling some callbacks may still be called with cancelled = false
FISHNETS_API void Executor_cancelTimer(Executor& ex, uint64_t id);
FISHNETS_API void Executor_cancelAllTimers(Executor& ex);

inline void Executor_startTimer(const ExecutorPtr& ex, uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb) {
    Executor_startTimer(*ex, id, timeFromNow, std::move(cb));
}
inline void Executor_cancelTimer(const ExecutorPtr& ex, uint64_t id) {
    Executor_cancelTimer(*ex, id);
}
inline void Executor_cancelAllTimers(const ExecutorPtr& ex) {
    Executor_cancelAllTimers(*ex);
}

} // namespace fishnets
