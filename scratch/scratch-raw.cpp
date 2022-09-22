// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#define BOOST_BEAST_USE_STD_STRING_VIEW 1
#define BOOST_ASIO_USE_TS_EXECUTOR_AS_DEFAULT 1
#if defined(_MSC_VER)
#   pragma warning (disable: 4100)
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>

#include <string>
#include <iostream>
#include <thread>

#include <itlib/span.hpp>
#include <memory>
#include <string_view>
#include <functional>
#include <optional>
#include <vector>

namespace net = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace http = beast::http;
using tcp = net::ip::tcp;

class WebSocketSession;
using WebSocketSessionPtr = std::shared_ptr<WebSocketSession>;

class WebSocketServer;
class SessionOwner;

class WebSocketSession : public std::enable_shared_from_this<WebSocketSession>
{
public:
    WebSocketSession();
    ~WebSocketSession();

    WebSocketSession(const WebSocketSession&) = delete;
    WebSocketSession& operator=(const WebSocketSession&) = delete;
    WebSocketSession(WebSocketSession&&) noexcept = delete;
    WebSocketSession& operator=(WebSocketSession&&) noexcept = delete;

    void postWSIOTask(std::function<void()> task);
    virtual void wsOpened();
    virtual void wsClosed();
    void wsClose();

    virtual void wsReceivedBinary(itlib::span<uint8_t> binary);
    virtual void wsReceivedText(itlib::span<char> text);

    void wsSend(itlib::span<const uint8_t> binary);
    void wsSend(std::string_view text);
    virtual void wsCompletedSend();

    std::string_view wsTarget() const;

private:
    friend class WebSocketServer;
    friend class SessionOwner;

    SessionOwner* m_owner = nullptr;

    // used for posting IO tasks
    net::executor m_executor;

    void opened(SessionOwner& session);
    void closed();
};

///////////////////////////////////////////////////////////////////////////////
// session

class SessionOwner : public std::enable_shared_from_this<SessionOwner>
{
public:
    websocket::stream<tcp::socket> m_ws;

    SessionOwner(tcp::socket&& socket)
        : m_ws(std::move(socket))
    {}

    ~SessionOwner()
    {
        m_session->closed();
    }

    // accept flow

    void accept()
    {
        // read upgrade request to accept
        http::async_read(m_ws.next_layer(), m_readBuf, m_upgradeRequest,
            beast::bind_front_handler(&SessionOwner::onUpgradeRequest, shared_from_this()));
    }


    void onUpgradeRequest(beast::error_code e, size_t /*bytesTransfered*/)
    {
        if (e) return failed(e, "upgrade");
        if (!websocket::is_upgrade(m_upgradeRequest)) {
            return failed(websocket::error::no_connection_upgrade, "upgrade");
        }
        m_target = m_upgradeRequest.target();
        m_ws.async_accept(m_upgradeRequest,
            beast::bind_front_handler(&SessionOwner::onConnectionEstablished, shared_from_this()));
        m_readBuf.clear();
    }

    // connections

    void doClose(websocket::close_code code)
    {
        m_ws.async_close(code, beast::bind_front_handler(&SessionOwner::onClosed, shared_from_this()));
    }

    void onClosed(beast::error_code e)
    {
        if (e) return failed(e, "close");
    }

    void onConnectionEstablished(beast::error_code e)
    {
        if (e) return failed(e, "establish");

        // clear request to save memory
        // it won't be needed any more
        // (in case of clients it's already empty so this line would be redundant)
        m_upgradeRequest = {};

        m_session->opened(*this);

        doRead();
    }

    // io

    void onReadCB(beast::error_code e, size_t)
    {
        onRead(e, m_ws.got_text());
    }

    void doRead()
    {
        m_ws.async_read(m_readBuf, beast::bind_front_handler(&SessionOwner::onReadCB, shared_from_this()));
    }

    void onRead(beast::error_code e, bool text)
    {
        if (e == websocket::error::closed) return closed();
        if (e) return failed(e, "read");

        auto bufData = m_readBuf.data().data();
        if (text)
        {
            m_session->wsReceivedText(itlib::make_span(static_cast<char*>(bufData), m_readBuf.size()));
        }
        else
        {
            m_session->wsReceivedBinary(itlib::make_span(static_cast<uint8_t*>(bufData), m_readBuf.size()));
        }

        m_readBuf.clear();
        doRead();
    }

    void write(bool text, net::const_buffer buf)
    {
        assert(!m_writing);
        m_writing = true;
        doWrite(text, buf);
    }

    void doWrite(bool text, net::const_buffer buf)
    {
        m_ws.text(text);
        m_ws.async_write(buf, beast::bind_front_handler(&SessionOwner::onWrite, shared_from_this()));
    }

    void onWrite(beast::error_code e, size_t)
    {
        if (e) return failed(e, "write");
        m_writing = false;
        m_session->wsCompletedSend();
    }

    // util

    void setInitialServerOptions()
    {
        m_ws.read_message_max(16 * 1024 * 1024);

        using bsb = websocket::stream_base;
        auto timeout = bsb::timeout::suggested(beast::role_type::server);
        m_ws.set_option(timeout);

        auto id = std::string("ws-server ") + BOOST_BEAST_VERSION_STRING;
        m_ws.set_option(bsb::decorator([id = std::move(id)](websocket::response_type& res) {
            res.set(http::field::server, id);
        }));
    }

    void failed(beast::error_code e, const char* source)
    {
        std::cerr << source << " error: " << e.message() << '\n';
    }

    void closed()
    {
        std::cout << "session closed\n";
    }

    void setSession(WebSocketSessionPtr&& session)
    {
        m_sessionPayload = std::move(session);
        m_session = m_sessionPayload.get();
    }

    beast::flat_buffer m_readBuf;
    WebSocketSessionPtr m_sessionPayload;
    WebSocketSession* m_session = nullptr; // quick access pointer

    // only relevant when accepting
    // cleared after the connection is established
    http::request<http::string_body> m_upgradeRequest;

    // only relevant when connecting
    std::string m_host;

    // target of web socket connection (typically "/")
    std::string m_target;

    bool m_writing = false;
};

///////////////////////////////////////////////////////////////////////////////
// WebSocketSession

WebSocketSession::WebSocketSession() = default;

WebSocketSession::~WebSocketSession() = default;

void WebSocketSession::opened(SessionOwner& session)
{
    assert(!m_owner);
    m_owner = &session;
    wsOpened();
}

void WebSocketSession::closed()
{
    m_owner = nullptr;
    wsClosed();
}

void WebSocketSession::postWSIOTask(std::function<void()> task)
{
    net::dispatch(m_executor,
        [self = shared_from_this(), task = std::move(task)]() {
            assert(self); // this can only fail if we're posting a taks in the session's destructor, which is definitely not a good idea
            task();
        }
    );
}

void WebSocketSession::wsOpened() {}
void WebSocketSession::wsClosed() {}

void WebSocketSession::wsClose()
{
    if (!m_owner) return; // already closed
    m_owner->doClose(websocket::close_code::normal);
}

void WebSocketSession::wsReceivedBinary(itlib::span<uint8_t>) {}
void WebSocketSession::wsReceivedText(itlib::span<char>) {}

void WebSocketSession::wsSend(itlib::span<const uint8_t> binary)
{
    if (!m_owner)
    {
        std::cerr << "Ignore write on closed session\n";
        return;
    }

    m_owner->write(false, net::buffer(binary.data(), binary.size()));
}

void WebSocketSession::wsSend(std::string_view text)
{
    if (!m_owner)
    {
        std::cerr << "Ignore write on closed session\n";
        return;
    }

    m_owner->write(true, net::buffer(text));
}

void WebSocketSession::wsCompletedSend() {}

std::string_view WebSocketSession::wsTarget() const
{
    if (!m_owner) return {};
    return m_owner->m_target;
}

///////////////////////////////////////////////////////////////////////////////
// server

class WebSocketServer
{
public:
    WebSocketServer(uint16_t port, int numThreads)
        : m_ctx(numThreads)
        , m_acceptor(m_ctx, tcp::endpoint(tcp::v4(), port))
    {
        doAccept();
        m_threads.reserve(size_t(numThreads));
        for (int i = 0; i < numThreads; ++i)
        {
            m_threads.emplace_back([this]() { m_ctx.run(); });
        }
    }

    ~WebSocketServer()
    {
        m_ctx.stop();
        for (auto& thread : m_threads)
        {
            thread.join();
        }
    }

    void doAccept()
    {
        m_acceptor.async_accept(net::make_strand(m_ctx), beast::bind_front_handler(&WebSocketServer::onAccept, this));
    }

    void onAccept(beast::error_code e, tcp::socket socket)
    {
        if (e)
        {
            std::cerr << "onAccept error: " << e << '\n';
            return;
        }

        // init session and owner
        auto session = std::make_shared<WebSocketSession>();

        auto owner = std::make_shared<SessionOwner>(std::move(socket));
        owner->setInitialServerOptions();
        //session->m_executor = owner->m_ws.get_executor();
        owner->setSession(std::move(session));

        // and initiate
        owner->accept();

        // accept more sessions
        doAccept();
    }

    net::io_context m_ctx;

    tcp::acceptor m_acceptor;

    std::vector<std::thread> m_threads;
};

void client(const std::string msg, const int num, const int ms)
{
    net::io_context m_ctx;
    tcp::resolver resolver(m_ctx);
    auto results = resolver.resolve(tcp::v4(), "localhost", "7654");
    if (results.empty())
    {
        std::cerr << "Could not resolve localhost\n";
        return;
    }

    websocket::stream<tcp::socket> ws(m_ctx);
    beast::get_lowest_layer(ws).connect(results.begin()->endpoint());

    ws.handshake("localhost:7654", "/");

    ws.text(true);

    for (auto i = 0; i < num; ++i) {
        ws.write(net::buffer(msg + ' ' + std::to_string(i)));
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    ws.close(websocket::close_code::normal);
}

int main()
{
    WebSocketServer server(7654, 2);
    //while (true) std::this_thread::yield;

    std::vector<std::thread> clients;
    clients.emplace_back([]() {
        client("the rain in spain stays mainly on the plain", 10, 20);
    });
    clients.emplace_back([]() {
        client("she sells sea shells on the sea shore", 8, 30);
    });
    clients.emplace_back([]() {
        client("six swiss withces with swatch watches", 9, 25);
    });
    for (auto& c : clients) {
        c.join();
    }

    return 0;
};