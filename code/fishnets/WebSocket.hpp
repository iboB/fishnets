// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "Executor.hpp"
#include <itlib/ufunction.hpp>
#include <itlib/span.hpp>
#include <itlib/expected.hpp>
#include <memory>
#include <string>

namespace fishnets {

struct EndpointInfo;
class Executor;

class FISHNETS_API WebSocket {
public:
    struct Impl;
    explicit WebSocket(std::unique_ptr<Impl>);
    ~WebSocket();

    WebSocket(WebSocket&&) noexcept;
    WebSocket& operator=(WebSocket&&) noexcept;

    // post a task to be executed after a timeout
    // the callback will be called with the id of the timer and whether it was cancelled
    // the associated task will extend the lifetime of the handler until the callback is called
    // starting a timer with a given id will cancel any previous timer with the same id
    using TimerCb = itlib::ufunction<void(uint64_t id, bool cancelled)>;
    void startTimer(uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb);

    // due to the async nature of the system, after cancelling some callbacks may still be called with cancelled = false
    void cancelTimer(uint64_t id);
    void cancelAllTimers();

    bool connected() const;

    using ByteSpan = itlib::span<uint8_t>;

    struct Packet {
        ByteSpan data;
        bool complete; // true if the data completes a frame
        bool text; // true if the data is text
    };

    // call to initiate a receive
    // only a single receive is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding callback is called
    // calls to recv without the corresponding callback of the previous receive being called result in UB
    // the argument is a span to be filled with the received data or an empty span in which case an
    // internal growable buffer will be used (complete in completion handler will always be true)
    // the buffer argment of the callback is the span provided as a first argument (or a view of the internal buffer)
    // it will be resized to the size of the received data
    using RecvResult = itlib::expected<Packet, std::string>;
    using RecvCb = itlib::ufunction<void(RecvResult)>;
    void recv(ByteSpan buf, RecvCb cb);

    // call to initiate a send
    // only a single send is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding callback is called
    // calls to send without the corresponding callback of the previous send being called result in undefined behavior
    // with complete = false, a partial packet can be sent
    // sending heterogeneous (text-binary) partial packets is not supported
    // the first packet in a chain determines the type, the types of the rest until complete are ignored
    using SendCb = itlib::ufunction<void(itlib::expected<void, std::string>)>;
    void send(Packet buf, SendCb cb);

    // call to initiate the close of the session
    using CloseCb = itlib::ufunction<void()>;
    void close(CloseCb cb);

    // get the endpoint info of the connection
    EndpointInfo getEndpointInfo() const;

    const ExecutorPtr& executor() const;
private:
    std::unique_ptr<Impl> m_impl;
};

} // namespace fishnets
