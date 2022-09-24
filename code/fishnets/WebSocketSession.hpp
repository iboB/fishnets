// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"

#include <itlib/span.hpp>
#include <memory>
#include <string_view>
#include <functional>

namespace fishnets
{
class Server;
class Client;
class SessionOwnerBase;
class ExecutorHolder;
struct WebSocketEndpointInfo;
struct WebSocketSessionOptions;

// the lifetime of a session is managed via a shared pointer to this
class FISHNETS_API WebSocketSession
{
public:
    WebSocketSession(const WebSocketSession&) = delete;
    WebSocketSession& operator=(const WebSocketSession&) = delete;
    WebSocketSession(WebSocketSession&&) noexcept = delete;
    WebSocketSession& operator=(WebSocketSession&&) noexcept = delete;

    // will be called on the IO thread shortly after construction to get the initial options.
    // no calls to the interface are allowed in this function, not even postWSIOTask
    // the default implementation returns default-constructed WebSocketSessionOptions
    virtual WebSocketSessionOptions getInitialOptions();

    // post a task to be executed on the io thread of the session
    // THIS IS THE ONLY FUNCTION WHICH IS VALID ON ANY THREAD
    // ONLY CALL wsSend and wsClose from within a posted task
    // posting a task will extend the lifetime of the posting session until the task is complete
    // thus capturing [this] or members by ref, when posting from a session, is safe
    void postWSIOTask(std::function<void()> task);

    // called when socked connection is established
    virtual void wsOpened();

    // called when connection is closed
    virtual void wsClosed();

    // call to initiate the close of the session
    void wsClose();

    // called when data is received
    virtual void wsReceivedBinary(itlib::span<uint8_t> binary);
    virtual void wsReceivedText(itlib::span<char> text);

    // call to initiate a send
    // only a single write is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding wsCompletedSend or wsClosed is called
    // calls to send without the corresponding wsCompletedSend of the previous send being received result in undefined behavior
    void wsSend(itlib::span<const uint8_t> binary);
    void wsSend(std::string_view text);
    virtual void wsCompletedSend();

    // optional heartbeat function to be called periodically
    // based on the heartbeatInterval option
    // invoked in IO thread if enabled
    // NOTE that the argument is the millisecond time provided as an option
    // the execution may potentially be delayed due to heavy io tasks, so this is not necessarily
    // the time since the last invocation
    virtual void wsHeartbeat(uint32_t ms);

    WebSocketEndpointInfo wsGetEndpointInfo() const;

    void wsSetOptions(const WebSocketSessionOptions& options);

    // target of the request which initiated the session
    // will be an empty string on sessions which are not connected
    std::string_view wsTarget() const;

protected:
    WebSocketSession();
    // intentionally not virtual. Objects are not owned through this, but instead through shared pointers
    ~WebSocketSession();

private:
    friend class Server;
    friend class Client;
    friend class SessionOwnerBase;

    SessionOwnerBase* m_owner = nullptr;

    // used for posting IO tasks
    std::unique_ptr<ExecutorHolder> m_ioExecutorHolder;

    void opened(SessionOwnerBase& session);
    void closed();
};

} // namespace fishnets
