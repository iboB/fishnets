// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsSessionHandler.hpp"
#include "../EndpointInfo.hpp"
#include "../Post.hpp"
#include "../Timer.hpp"
#include <itlib/throw_ex.hpp>
#include <cstdio>

namespace fishnets {

using throw_ex = itlib::throw_ex<std::runtime_error>;

WsSessionHandler::WsSessionHandler() = default;
WsSessionHandler::~WsSessionHandler() = default;

void WsSessionHandler::postWsIoTask(Task task) {
    Executor_post(m_executor, std::move(task));
}

void WsSessionHandler::wsStartTimer(uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb) {
    Executor_startTimer(m_executor, id, timeFromNow, std::move(cb));
}
void WsSessionHandler::wsCancelTimer(uint64_t id) {
    Executor_cancelTimer(m_executor, id);
}
void WsSessionHandler::wsCancelAllTimers() {
    Executor_cancelAllTimers(m_executor);
}

bool WsSessionHandler::wsIsOpen() const {
    return m_ws && m_ws->connected();
}

void WsSessionHandler::tryCallWsClosed() {
    if (m_closeStatus.open()) return; // not closed yet

    // check for active async ops
    if (m_closeStatus.send == CloseStatus::active) return;
    if (m_closeStatus.recv == CloseStatus::active) return;
    if (m_closeStatus.close == CloseStatus::active) return;

    // no active async ops
    m_ws.reset();
    wsClosed(std::move(*m_closeStatus.reason));
}

void WsSessionHandler::wsClose() {
    if (!m_closeStatus.open()) return; // close pending
    if (m_closeStatus.close != CloseStatus::none) {
        throw_ex{} << "wsClose called twice";
    }
    m_closeStatus.close = CloseStatus::active;
    m_ws->close([this, pl = shared_from_this()](WebSocket::Result<void> res) {
        m_closeStatus.close = CloseStatus::closed;
        if (m_closeStatus.open()) {
            // this is the first close, so we set the reason
            if (res) {
                m_closeStatus.reason = "user closed";
            }
            else {
                m_closeStatus.reason = "closed with error: " + res.error();
            }
        }
        tryCallWsClosed();
    });
}

void WsSessionHandler::wsReceive(WebSocket::ByteSpan buf) {
    if (!m_closeStatus.open()) return; // close pending
    if (m_closeStatus.recv != CloseStatus::none) {
        throw_ex{} << "wsReceive called twice";
    }
    m_closeStatus.recv = CloseStatus::active;
    m_ws->recv(buf, [this, pl = shared_from_this()](WebSocket::Result<WebSocket::Packet> res) {
        if (res) {
            m_closeStatus.recv = CloseStatus::none; // can receive again
            if (res->text) {
                static_assert(sizeof(char) == sizeof(*res->data.data()));
                itlib::span<char> text{reinterpret_cast<char*>(res->data.data()), res->data.size()};
                wsReceivedText(text, res->complete);
            }
            else {
                wsReceivedBinary(res->data, res->complete);
            }
        }
        else {
            m_closeStatus.recv = CloseStatus::closed;
            if (m_closeStatus.open()) {
                m_closeStatus.reason = "receive error: " + res.error();
            }
        }
        tryCallWsClosed();
    });
}

void WsSessionHandler::doSend(WebSocket::ConstPacket packet) {
    if (!m_closeStatus.open()) return; // close pending
    if (m_closeStatus.send != CloseStatus::none) {
        throw_ex{} << "wsSend called twice";
    }
    m_closeStatus.send = CloseStatus::active;
    m_ws->send(packet, [this, pl = shared_from_this()](WebSocket::Result<void> res) {
        if (res) {
            m_closeStatus.send = CloseStatus::none;
            wsCompletedSend();
        }
        else {
            m_closeStatus.send = CloseStatus::closed;
            if (m_closeStatus.open()) {
                m_closeStatus.reason = "send error: " + res.error();
            }
        }
        tryCallWsClosed();
    });
}

void WsSessionHandler::wsSend(itlib::span<const uint8_t> binary, bool complete) {
    doSend({binary, complete, false});

}
void WsSessionHandler::wsSend(std::string_view text, bool complete) {
    doSend({itlib::span(text).as_bytes(), complete, true});
}

EndpointInfo WsSessionHandler::wsGetEndpointInfo() const {
    return m_ws->getEndpointInfo();
}

void WsSessionHandler::wsSetOptions(const WebSocketOptions& options) {
    m_ws->setOptions(options);
}

void WsSessionHandler::onConnected(WebSocketPtr ws, std::string_view target) {
    m_ws = std::move(ws);
    m_executor = m_ws->executor();
    wsOpened(target);
}

// default implementations
void WsSessionHandler::wsOpened(std::string_view) {}
void WsSessionHandler::wsClosed(std::string msg) {
    printf("WebSocket disconnected: %s\n", msg.c_str());
}
void WsSessionHandler::wsReceivedBinary(itlib::span<uint8_t>, bool) {}
void WsSessionHandler::wsReceivedText(itlib::span<char>, bool) {}
void WsSessionHandler::wsCompletedSend() {}

} // namespace fishnets
