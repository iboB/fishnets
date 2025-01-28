// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"

#include <itlib/span.hpp>
#include <itlib/shared_from.hpp>

namespace fishnets {

namespace impl {
class Executor;
class Socket;
}

class SessionOptions;
class ErrorCode;

class SessionHandler : public itlib::enable_shared_from {
public:
    SessionHandler(const SessionHandler&) = delete;
    SessionHandler& operator=(const SessionHandler&) = delete;

    // will be called on the IO thread shortly after construction to get the initial options.
    // no calls to the interface are allowed in this function, not even postSessionIoTask
    // the default implementation returns default-constructed WebSocketSessionOptions
    virtual SessionOptions getInitialOptions();

    // post a task to be executed on the io thread of the session
    // THIS IS THE ONLY FUNCTION WHICH IS VALID ON ANY THREAD
    // ONLY CALL shSend, shRecv, and shClose from within a posted task
    // posting a task will not extend the lifetime of the posting session, so be careful to capture sgared pointers
    void postSessionIoTask(std::function<void()> task);

    // entrypoint
    // called when socked connection is established
    // io ops (including postIoTask) are allowed from this point on
    virtual void shOpened();

    // call to initiate the close of the session
    void shClose();

    using RecvCb = std::function<void(itlib::span<uint8_t> buf, bool binary, bool complete, ErrorCode ec)>;
    void shRecv(itlib::span<uint8_t> buf, RecvCb cb);

    // call to initiate a send
    // only a single send is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding callback is called
    // calls to send without the corresponding callback of the previous send being received result in undefined behavior
    // with complete = false, a partial packet can be sent
    // sending heterogeneous (text-binary) partial packets is not supported
    // the first packet in a chain determines the type
    using SendCb = std::function<void(ErrorCode)>;
    void shSend(itlib::span<uint8_t> binary, bool complete, SendCb cb);
    void shSend(std::string_view text, bool complete, SendCb cb);

protected:
    SessionHandler();
    // intentionally not virtual. Objects are not owned through this, but instead through shared pointers
    ~SessionHandler();

private:
    std::unique_ptr<impl::Executor> m_executor;
    std::unique_ptr<impl::Socket> m_socket;
};

}
