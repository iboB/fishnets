// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "../API.h"
#include "../WebSocket.hpp"

#include <itlib/span.hpp>
#include <itlib/shared_from.hpp>
#include <itlib/ufunction.hpp>
#include <cstdint>
#include <chrono>
#include <string_view>

namespace fishnets {

class Executor;
struct WsSessionOptions;
struct EndpointInfo;

// utility class for handling a websocket session
// wraps a WebSocket object and provides a callback interface for handling the session
class FISHNETS_API WsSessionHandler : public itlib::enable_shared_from {
public:
    WsSessionHandler(const WsSessionHandler&) = delete;
    WsSessionHandler& operator=(const WsSessionHandler&) = delete;

    // will be called on the IO thread shortly after construction to get the initial options.
    // no calls to the interface are allowed in this function, not even postSessionIoTask
    // the default implementation returns default-constructed WsSessionOptions
    virtual WsSessionOptions getInitialOptions();

    // post a task to be executed on the io thread of the session
    // THIS IS THE ONLY FUNCTION WHICH IS VALID ON ANY THREAD
    // ONLY CALL the other ws* functions from within a posted task
    // posting a task will extend the lifetime of the posting handler until the task is complete
    // thus capturing [this] or members by ref, when posting from a handler, is safe
    void postWsIoTask(itlib::ufunction<void()> task);

    // timer interface
    // AGAIN: THIS IS ONLY VALID ON THE IO THREAD (from a posted task or io callback)
    // extends the lifetime of the session handler until the callback is called
    using TimerCb = itlib::ufunction<void(uint64_t id, bool cancelled)>;
    void wsStartTimer(uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb);
    void wsCancelTimer(uint64_t id);
    void wsCancelAllTimers();

    // entrypoint
    // called when socked connection is established
    // with the target of the request which initiated the session
    // io ops (including postIoTask) are only allowed from this point on
    virtual void wsOpened(std::string_view target);

    // called when connection is closed
    // no io callbacks (wsReceived*, wsCompletedSend) will be called after this (calling wsReceive and wsSend is safe)
    // wsio tasks and timers will still be executed and new ones can still be posted after this
    // note that this cannot be called unless there are io ops in progress or wsClose has been called
    virtual void wsClosed();

    // call to check if the session is open
    bool wsIsOpen() const;

    // call to initiate the close of the session
    // will result in wsClosed being called
    void wsClose();

    // call to initiate a receive
    // the lifetime of the session handler itself will be extended until the corresponding wsReceived* is called
    void wsReceive(itlib::span<uint8_t> buf);

    // the buffer argment of these callbacks is the span provided to wsReceive (or a view of the internal buffer)
    // it will be resized to the size of the received data
    // complete will be true if the data completes the frame
    virtual void wsReceivedBinary(itlib::span<uint8_t> binary, bool complete);
    virtual void wsReceivedText(itlib::span<char> text, bool complete);

    // call to initiate a send
    // the lifetime of the session handler will be extended until the corresponding wsCompletedSend is called
    void wsSend(itlib::span<const uint8_t> binary, bool complete = true);
    void wsSend(std::string_view text, bool complete = true);
    virtual void wsCompletedSend();

    EndpointInfo wsGetEndpointInfo() const;

    // set options for the session
    void wsSetOptions(const WsSessionOptions& options);

protected:
    WsSessionHandler();
    // intentionally not virtual. Objects are not owned through this, but instead through shared pointers
    ~WsSessionHandler();

private:
    WebSocket m_ws;
    std::shared_ptr<Executor> m_executor;
};

} // namespace fishnets
