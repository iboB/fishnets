// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "../API.h"
#include "../WebSocket.hpp"
#include "../WsConnectionHandler.hpp"
#include "../Task.hpp"

#include <itlib/shared_from.hpp>
#include <string_view>
#include <optional>

namespace fishnets {

struct WebSocketOptions;
struct EndpointInfo;

// utility class for handling a websocket session
// wraps a WebSocket object and provides a callback interface for handling the session
class FISHNETS_API WsSessionHandler : public WsConnectionHandler, public itlib::enable_shared_from {
public:
    WsSessionHandler(const WsSessionHandler&) = delete;
    WsSessionHandler& operator=(const WsSessionHandler&) = delete;

    // will be called on the IO strand shortly after construction to get the initial options.
    // no calls to the interface are allowed in this function, not even postSessionIoTask
    // the default implementation returns default-constructed WebSocketOptions
    // this comes from WsConnectionHandler and you can override it if you want to provide custom initial options
    // virtual WebSocketOptions getInitialOptions() override;

    // post a task to be executed on the io strand of the session
    // THIS IS THE ONLY FUNCTION WHICH IS VALID ON ANY THREAD
    // ONLY CALL the other ws* functions from within a posted task
    // posting a task will extend the lifetime of the posting handler until the task is complete
    // thus capturing [this] or members by ref, when posting from a handler, is safe
    void postWsIoTask(Task task);

    const ExecutorPtr& wsExecutor() const { return m_executor; }

protected:
    WsSessionHandler();
    // intentionally not virtual. Objects are not owned through this, but instead through shared pointers
    ~WsSessionHandler();

    // called on connection errors before wsOpened
    // once wsOpened is called this can never get called, instead wsClosed will be called
    // this comes from WsConnectionHandler and you can override it if you want to handle connection errors
    // virtual void onConnectionError(std::string message) override;

    // entrypoint
    // called when socked connection is established
    // with the target of the request which initiated the session
    // io ops (including postIoTask) are only allowed from this point on
    virtual void wsOpened(std::string_view target);

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

    // the buffer argment of these callbacks is the span provided to wsReceive (or a view of the internal buffer)
    // it will be resized to the size of the received data
    // complete will be true if the data completes the frame
    virtual void wsReceivedBinary(std::span<uint8_t> binary, bool complete);
    virtual void wsReceivedText(std::span<char> text, bool complete);

    // call to initiate a send
    // the lifetime of the session handler will be extended until the corresponding wsCompletedSend is called
    void wsSend(std::span<const uint8_t> binary, bool complete = true);
    void wsSend(std::string_view text, bool complete = true);
    virtual void wsCompletedSend();

    EndpointInfo wsGetEndpointInfo() const;

    // set options for the session
    void wsSetOptions(const WebSocketOptions& options);

private:
    virtual void onConnected(WebSocketPtr ws, std::string_view target) final override;

    WebSocketPtr m_ws;
    ExecutorPtr m_executor;

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

    void doSend(WebSocket::ConstPacket packet);
    void tryCallWsClosed();
};

} // namespace fishnets
