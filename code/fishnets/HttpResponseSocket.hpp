// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "ExecutorPtr.hpp"
#include <itlib/ufunction.hpp>
#include <itlib/expected.hpp>
#include <string>
#include <span>

namespace fishnets {

class FISHNETS_API HttpResponseSocket {
public:
    virtual ~HttpResponseSocket();

    HttpResponseSocket(const HttpResponseSocket&) = delete;
    HttpResponseSocket& operator=(const HttpResponseSocket&) = delete;

    template <typename T>
    using Result = itlib::expected<T, std::string>;

    // call to initiate the close of the session
    using CloseCb = itlib::ufunction<void(Result<void>)>;
    virtual void close(CloseCb cb) = 0;

    const ExecutorPtr& executor() const { return m_executor; }
private:
    // sealed interface
    HttpResponseSocket();
    friend struct HttpResponseSocketImpl;

    ExecutorPtr m_executor;
};

} // namespace fishnets
