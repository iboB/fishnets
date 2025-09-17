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

    virtual bool connected() const = 0;

    using ByteSpan = std::span<uint8_t>;
    struct Packet {
        ByteSpan data;
        bool complete; // true if the data completes the response
    };

    // call to initiate a receive
    // only a single receive is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding callback is called
    // calls to recv without the corresponding callback of the previous receive being called result in UB
    // the argument is a span to be filled with the received data
    // the buffer argument of the callback is the span provided as a first argument
    // it will be resized to the size of the received data
    using RecvCb = itlib::ufunction<void(itlib::expected<Packet, std::string>)>;
    virtual void recv(ByteSpan span, RecvCb cb) = 0;

    // call to initiate the close of the session
    virtual void close() = 0;

    const ExecutorPtr& executor() const { return m_executor; }
private:
    // sealed interface
    HttpResponseSocket();
    friend struct HttpResponseSocketImpl;

    ExecutorPtr m_executor;
};

} // namespace fishnets
