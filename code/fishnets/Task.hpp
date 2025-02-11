// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "ExecutorPtr.hpp"
#include <itlib/ufunction.hpp>

namespace fishnets {
using Task = itlib::ufunction<void()>;

FISHNETS_API void post(Executor& ex, Task task);

void post(const ExecutorPtr& ex, Task task) {
    post(*ex, std::move(task));
}
} // namespace fishnets
