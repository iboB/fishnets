// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include "ExecutorPtr.hpp"
#include <itlib/ufunction.hpp>
#include <itlib/span.hpp>
#include <itlib/expected.hpp>
#include <memory>
#include <string>

namespace fishnets {

struct EndpointInfo;
struct WebSocketOptions;
class WsSessionHandler;
class Executor;

class FISHNETS_API WebSocket {
public:
    virtual ~WebSocket();

    WebSocket(const WebSocket&) = delete;
    WebSocket& operator=(const WebSocket&) = delete;

    virtual bool connected() const = 0;

    using ByteSpan = itlib::span<uint8_t>;
    using ConstByteSpan = itlib::span<const uint8_t>;

    struct Packet {
        ByteSpan data;
        bool complete; // true if the data completes a frame
        bool text; // true if the data is text
    };

    struct ConstPacket {
        ConstPacket() = default;
        ConstPacket(const ConstPacket&) = default;
        ConstPacket& operator=(const ConstPacket&) = default;
        ConstPacket(const Packet& p) : data(p.data), complete(p.complete), text(p.text) {}
        ConstPacket& operator=(const Packet& p) { data = p.data; complete = p.complete; text = p.text; return *this; }
        ConstPacket(ConstByteSpan d, bool c, bool t) : data(d), complete(c), text(t) {}
        ConstByteSpan data;
        bool complete; // true if the data completes a frame
        bool text; // true if the data is text
    };

    template <typename T>
    using Result = itlib::expected<T, std::string>;

    // call to initiate a receive
    // only a single receive is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding callback is called
    // calls to recv without the corresponding callback of the previous receive being called result in UB
    // the argument is a span to be filled with the received data or an empty span in which case an
    // internal growable buffer will be used (complete in completion handler will always be true)
    // the buffer argment of the callback is the span provided as a first argument (or a view of the internal buffer)
    // it will be resized to the size of the received data
    using RecvCb = itlib::ufunction<void(Result<Packet>)>;
    virtual void recv(ByteSpan span, RecvCb cb) = 0;

    // call to initiate a send
    // only a single send is supported at a time
    // the lifetime of the memory viewed must be preserved until the corresponding callback is called
    // calls to send without the corresponding callback of the previous send being called result in undefined behavior
    // with complete = false, a partial packet can be sent
    // sending heterogeneous (text-binary) partial packets is not supported
    // the first packet in a chain determines the type, the types of the rest until complete are ignored
    using SendCb = itlib::ufunction<void(Result<void>)>;
    virtual void send(ConstPacket packet, SendCb cb) = 0;

    // call to initiate the close of the session
    using CloseCb = itlib::ufunction<void(Result<void>)>;
    virtual void close(CloseCb cb) = 0;

    // get the endpoint info of the connection
    virtual EndpointInfo getEndpointInfo() const = 0;

    // set options for the session
    virtual void setOptions(const WebSocketOptions& options) = 0;

    const ExecutorPtr& executor() const { return m_executor; }
private:
    // sealed interface
    WebSocket();
    friend struct WebSocketImpl;

    ExecutorPtr m_executor;
};

} // namespace fishnets
