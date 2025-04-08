// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <doctest/doctest.h>
#include <mutex>
#include <memory>

// sequencing checks
// checks that io calls are strictly sequenced
// it's an interface so as to have a noop implementation
// thus not all sessions will have sequencing checks in case these sequencing checks improve the actual sequencing

struct SeqCheckBase {
    virtual ~SeqCheckBase() = default;
    virtual void lock() = 0;
    virtual void unlock() = 0;
};

struct NoopSeqCheck final : SeqCheckBase {
    virtual void lock() override {}
    virtual void unlock() override {}
};

struct StrictSeqCheck final : SeqCheckBase {
    std::mutex mut;
    virtual void lock() override {
        REQUIRE(mut.try_lock());
    }
    virtual void unlock() override {
        mut.unlock();
    }
};

std::unique_ptr<SeqCheckBase> makeSeqCheck(bool strict) {
    if (strict) {
        return std::make_unique<StrictSeqCheck>();
    }
    return std::make_unique<NoopSeqCheck>();
}
