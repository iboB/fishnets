// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"

#include <itlib/span.hpp>
#include <itlib/shared_from.hpp>
#include <itlib/ufunction.hpp>
#include <cstdint>
#include <chrono>
#include <string_view>

namespace fishnets {

namespace impl {
class Executor;
class WsSession;
}

struct WsSessionOptions;
struct EndpointInfo;

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

    // post a task to be executed after a timeout
    // AGAIN: THIS IS ONLY VALID ON THE IO THREAD (from a posted task or io callback)
    // the callback will be called with the id of the timer and whether it was cancelled
    // the associated task will extend the lifetime of the handler until the callback is called
    // starting a timer with a given id will cancel any previous timer with the same id
    using TimerCb = itlib::ufunction<void(uint64_t id, bool cancelled)>;
    void wsStartTimer(uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb);

    // due to the async nature of the system, after cancelling some callbacks may still be called with cancelled = false
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
    // only a single receive is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding wsReceived* is called
    // the lifetime of the session handler itself will be extended until the corresponding wsReceived* is called
    // calls to receive without the corresponding wsReceived* of the previous receive being called result in undefined behavior
    // the argument is span to be filled with the received data or an empty span in which case an
    // internal growable buffer will be used (complete in wsReceived* will always be true)
    void wsReceive(itlib::span<uint8_t> buf);

    // the buffer argment of these callbacks is the span provided to wsReceive (or a view of the internal buffer)
    // it will be resized to the size of the received data
    // complete will be true if the data completes the frame
    virtual void wsReceivedBinary(itlib::span<uint8_t> binary, bool complete);
    virtual void wsReceivedText(itlib::span<char> text, bool complete);

    // call to initiate a send
    // only a single send is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding wsCompletedSend is called
    // the lifetime of the session handler itself will be extended until the corresponding wsCompletedSend is called
    // calls to send without the corresponding wsCompletedSend of the previous send being called result in undefined behavior
    // with complete = false, a partial packet can be sent
    // sending heterogeneous (text-binary) partial packets is not supported
    // the first packet in a chain determines the type
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
    std::unique_ptr<impl::Executor> m_executor;
    std::unique_ptr<impl::WsSession> m_session;
};

} // namespace fishnets
