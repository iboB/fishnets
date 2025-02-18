// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "ExecutorPtr.hpp"
#include "Task.hpp"

namespace fishnets {
// these functions are valid on any thread

FISHNETS_API void post(Executor& ex, Task task);

inline void post(const ExecutorPtr& ex, Task task) {
    post(*ex, std::move(task));
}
} // namespace fishnets
