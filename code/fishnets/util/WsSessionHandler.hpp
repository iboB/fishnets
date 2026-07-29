// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "../API.h"
#include "../WebSocket.hpp"
#include "../WebSocketPtr.hpp"

#include <xeq/ufunc.hpp>
#include <itlib/shared_from.hpp>
#include <string_view>
#include <optional>

namespace fishnets {

struct WebSocketOptions;
struct EndpointInfo;

// utility class for handling a WebSocket session
// wraps a WebSocket object and provides a callback interface for handling the session
class FISHNETS_API WsSessionHandler : public itlib::enable_shared_from {
public:
    explicit WsSessionHandler(WebSocketPtr ws = {});

    WsSessionHandler(const WsSessionHandler&) = delete;
    WsSessionHandler& operator=(const WsSessionHandler&) = delete;

    // post a task to be executed on the io strand of the session
    // THIS IS THE ONLY FUNCTION WHICH IS VALID ON ANY THREAD
    // ONLY CALL the other ws* functions from within a posted task
    // posting a task will extend the lifetime of the posting handler until the task is complete
    // thus capturing [this] or members by ref, when posting from a handler, is safe
    using Task = xeq::ufunc<void()>;
    void postWsIoTask(Task task);

    const xeq::executor_ptr& wsExecutor() const { return m_executor; }
protected:
    // intentionally not virtual. Objects are not owned through this, but instead through shared pointers
    ~WsSessionHandler();

    // call to attach a WebSocket to this handler
    // should only be called once (though it it technically possible to detach and reattach)
    // only valid if no WebSocket is currently attached
    void wsAttach(WebSocketPtr ws);

    // call to detach the WebSocket from this handler
    // only valid if no io operations are in progress (wsReceive, wsSend, wsClose)
    // regarding not-yet-executed ws io tasks, use at your own risk
    // unless the executor is stopped, they will still be executed
    WebSocketPtr wsDetach();

    // call to check if there are any io operations in progress (wsReceive, wsSend, wsClose)
    bool wsHasIoOpsInProgress() const;

    // with autoReceive, after each successful receive, another one is automatically initiated
    // this can be changed at any time and will affect the next possible receive operation
    // note that simply setting this does not initiate a receive
    // if you want a receive loop from the get go, set this to true and call wsReceive after the WebSocket is attached
    void wsSetAutoReceive(bool set = true) { m_autoReceive = set; }
    bool wsIsAutoReceiving() const { return m_autoReceive; }

    // called when connection is closed
    // no io callbacks (wsReceived*, wsCompletedSend) will be called after this (calling wsReceive and wsSend is safe)
    // wsio tasks and timers will still be executed and new ones can still be posted after this
    // note that this cannot be called unless there are io ops in progress or wsClose has been called
    // the default implementation logs to stdout
    virtual void wsClosed(std::string reason);

    // call to check if the session is open
    bool wsIsOpen() const;

    // call to initiate the close of the session
    // will result in wsClosed being called
    void wsClose();

    // call to initiate a receive
    // the lifetime of the session handler itself will be extended until the corresponding wsReceived* is called
    void wsReceive(WebSocket::ByteSpan buf = {});

    // the buffer argument of these callbacks is the span provided to wsReceive (or a view of the internal buffer)
    // it will be resized to the size of the received data
    // complete will be true if the data completes the frame
    virtual void wsReceivedBinary(std::span<std::byte> binary, bool complete);
    virtual void wsReceivedText(std::span<char> text, bool complete);

    // call to initiate a send
    // the lifetime of the session handler will be extended until the corresponding wsCompletedSend is called
    void wsSend(std::span<const std::byte> binary, bool complete = true);
    void wsSend(std::string_view text, bool complete = true);
    virtual void wsCompletedSend();

    EndpointInfo wsGetEndpointInfo() const;

    // set options for the session
    void wsSetOptions(const WebSocketOptions& options);

private:
    WebSocketPtr m_ws;
    xeq::executor_ptr m_executor;

    // helper for the contract of not calling op callbacks after wsClosed
    struct CloseStatus {
        std::optional<std::string> reason;

        bool open() const noexcept { return !reason; }

        enum Type : uint8_t {
            none,
            active,
            closed,
        };
        Type send = none;
        Type recv = none;
        Type close = none;
    };
    CloseStatus m_closeStatus;

    bool m_autoReceive = false;

    void doSend(WebSocket::ConstPacket packet);
    void tryCallWsClosed();
};

} // namespace fishnets
