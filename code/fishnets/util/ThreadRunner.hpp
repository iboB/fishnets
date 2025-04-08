// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <thread>
#include <vector>
#include <cassert>

// run an asio-like context in multiple threads

namespace fishnets {
class ThreadRunner {
    std::vector<std::thread> m_threads; // would use jthread, but apple clang still doesn't support them
public:
    ThreadRunner() = default;

    template <typename Ctx>
    void start(Ctx& ctx, size_t n) {
        assert(m_threads.empty());
        if (!m_threads.empty()) return; // rescue
        m_threads.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            m_threads.push_back(std::thread([i, n, &ctx]() mutable {
                ctx.run();
            }));
        }
    }

    void join() {
        for (auto& t : m_threads) {
            t.join();
        }
        m_threads.clear();
    }

    template <typename Ctx>
    ThreadRunner(Ctx& ctx, size_t n) {
        start(ctx, n);
    }

    ~ThreadRunner() {
        join();
    }

    size_t size() const noexcept {
        return m_threads.size();
    }

    bool empty() const noexcept {
        return m_threads.empty();
    }
};

} // namespace fishnets
