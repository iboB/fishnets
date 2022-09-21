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
struct WebSocketEndpointInfo;

class Server;

struct WebSocketEndpointInfo;
using WebSocketSessionFactoryFunc = std::function<WebSocketSessionPtr(const WebSocketEndpointInfo&)>;

class WebSocketServer
{
public:
    WebSocketServer(
        WebSocketSessionFactoryFunc sessionFactory,
        uint16_t port,
        int numThreads = 1);
    ~WebSocketServer();

    WebSocketServer(const WebSocketServer&) = delete;
    WebSocketServer& operator=(const WebSocketServer&) = delete;
    WebSocketServer(WebSocketServer&&) noexcept = delete;
    WebSocketServer& operator=(WebSocketServer&&) noexcept = delete;

private:
    std::unique_ptr<Server> m_server;
};

class Server;
class SessionOwnerBase;
class ExecutorHolder;
struct WebSocketEndpointInfo;
struct WebSocketSessionOptions;

class WebSocketSession
{
public:
    WebSocketSession(const WebSocketSession&) = delete;
    WebSocketSession& operator=(const WebSocketSession&) = delete;
    WebSocketSession(WebSocketSession&&) noexcept = delete;
    WebSocketSession& operator=(WebSocketSession&&) noexcept = delete;

    virtual WebSocketSessionOptions getInitialOptions();
    void postWSIOTask(std::function<void()> task);
    virtual void wsOpened();
    virtual void wsClosed();
    void wsClose();

    virtual void wsReceivedBinary(itlib::span<uint8_t> binary);
    virtual void wsReceivedText(itlib::span<char> text);

    void wsSend(itlib::span<const uint8_t> binary);
    void wsSend(std::string_view text);
    virtual void wsCompletedSend();

    virtual void wsHeartbeat(uint32_t ms);

    WebSocketEndpointInfo wsGetEndpointInfo() const;

    void wsSetOptions(const WebSocketSessionOptions& options);

    std::string_view wsTarget() const;

protected:
    WebSocketSession();
    ~WebSocketSession();

private:
    friend class Server;
    friend class SessionOwnerBase;

    SessionOwnerBase* m_owner = nullptr;

    // used for posting IO tasks
    std::unique_ptr<ExecutorHolder> m_ioExecutorHolder;

    void opened(SessionOwnerBase& session);
    void closed();
};

struct WebSocketSessionOptions
{
    // id/name of host
    // for servers this will be set as the "Server" HTTP header field
    // for clients this will be set as the "User-Agent" HTTP header field
    std::optional<std::string> hostId;

    // max size of incoming message
    // messages larger than that will be ignored
    std::optional<size_t> maxIncomingMessageSize;

    // timeout after which to disconnect when the other side doesn't respond
    // note that this doesn't mean the time in which the other side hasn't communicated
    // "not respoding" is based on pings which the library does internally
    std::optional<std::chrono::milliseconds> idleTimeout;

    // interval for wsHeartBeat. 0 means never
    std::optional<std::chrono::milliseconds> heartbeatInterval;
};

struct WebSocketEndpointInfo
{
    std::string address;
    uint16_t port = 0;
};

class ExecutorHolder
{
public:
    ExecutorHolder(net::executor&& ex, const WebSocketSessionPtr& session)
        : executor(std::move(ex))
        , sessionSharedFromThis(session)
    {}

    net::executor executor;

    // a poor man's shared-from this implementation, to avoid actually inheriting std::enable_shared_from_this in sessions
    // and leave that (optional) inheritance to the user
    // it's used to extend the lifetime of the session when wsio tasks are posted so that
    // a plain [this] capture is possible in postWSIOTask
    std::weak_ptr<WebSocketSession> sessionSharedFromThis;
};

///////////////////////////////////////////////////////////////////////////////
// session

class SessionOwnerBase : public std::enable_shared_from_this<SessionOwnerBase>
{
public:
    ~SessionOwnerBase()
    {
        m_session->closed();
    }

    virtual net::executor executor() = 0;

    // accept flow

    virtual void accept() = 0;

    void onUpgradeRequest(beast::error_code e, size_t /*bytesTransfered*/)
    {
        if (e) return failed(e, "upgrade");
        if (!websocket::is_upgrade(m_upgradeRequest)) {
            return failed(websocket::error::no_connection_upgrade, "upgrade");
        }
        m_target = m_upgradeRequest.target();
        acceptUpgrade();
        m_readBuf.clear();
    }

    virtual void acceptUpgrade() = 0;

    // connect flow

    virtual void connect(tcp::endpoint endpoint) = 0;

    // connections

    virtual void doClose(websocket::close_code code) = 0;

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

    virtual void doRead() = 0;
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

    virtual void doWrite(bool text, net::const_buffer buf) = 0;

    void onWrite(beast::error_code e, size_t)
    {
        if (e) return failed(e, "write");
        m_writing = false;
        m_session->wsCompletedSend();
    }

    // util

    virtual WebSocketEndpointInfo getEndpointInfo() = 0;

    virtual void setInitialServerOptions(WebSocketSessionOptions opts) = 0;
    virtual void setInitialClientOptions(WebSocketSessionOptions opts) = 0;

    virtual void setOptions(const WebSocketSessionOptions& opts) = 0;

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

    void postHeartbeatTask(std::chrono::milliseconds ms)
    {
        m_heartbeatTimer->expires_after(ms);
        m_heartbeatTimer->async_wait([wself = weak_from_this(), ms](beast::error_code e) {
            if (e) return; // error
            auto self = wself.lock();
            if (!self) return; // destroyed
            self->m_session->wsHeartbeat(uint32_t(ms.count()));

            if (self->m_heartbeatTimer)
            {
                // only post another if the timer is sitll alive
                // wsHeartbeat may have disabled it
                self->postHeartbeatTask(ms);
            }
        });
    }

    void resetHeartbeatTimer(const std::optional<std::chrono::milliseconds>& duration)
    {
        auto ms = duration.value_or(std::chrono::milliseconds(0));
        if (ms.count() == 0)
        {
            m_heartbeatTimer.reset();
            return;
        }

        if (!m_heartbeatTimer)
        {
            m_heartbeatTimer.reset(new net::steady_timer(executor()));
        }

        postHeartbeatTask(ms);
    }

    beast::flat_buffer m_readBuf;
    WebSocketSessionPtr m_sessionPayload;
    WebSocketSession* m_session = nullptr; // quick access pointer

    std::unique_ptr<net::steady_timer> m_heartbeatTimer;

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

WebSocketSessionOptions WebSocketSession::getInitialOptions()
{
    return {};
}

void WebSocketSession::opened(SessionOwnerBase& session)
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
    net::dispatch(m_ioExecutorHolder->executor,
        [self = m_ioExecutorHolder->sessionSharedFromThis.lock(), task = std::move(task)]() {
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

void WebSocketSession::wsHeartbeat(uint32_t) {}

WebSocketEndpointInfo WebSocketSession::wsGetEndpointInfo() const
{
    if (!m_owner) return {};
    return m_owner->getEndpointInfo();
}

void WebSocketSession::wsSetOptions(const WebSocketSessionOptions& options)
{
    if (!m_owner) return;
    m_owner->setOptions(options);
}

std::string_view WebSocketSession::wsTarget() const
{
    if (!m_owner) return {};
    return m_owner->m_target;
}

namespace
{

template <typename Socket>
std::optional<WebSocketEndpointInfo> getEndpointInfoOf(const Socket& s)
{
    beast::error_code err;
    auto ep = beast::get_lowest_layer(s).remote_endpoint(err);
    // if there's an error, the socket has likely been disconnected
    if (err) return {};

    WebSocketEndpointInfo ret;
    ret.address = ep.address().to_string();
    ret.port = ep.port();
    return ret;
}

template <typename WS>
class SessionOwnerT : public SessionOwnerBase
{
public:
    SessionOwnerT(WS ws)
        : m_ws(std::move(ws))
    {}

    WS m_ws;

    net::executor executor() override final
    {
        return m_ws.get_executor();
    }

    std::shared_ptr<SessionOwnerT> shared_from_base()
    {
        return std::static_pointer_cast<SessionOwnerT>(shared_from_this());
    }

    void doClose(websocket::close_code code) override final
    {
        m_ws.async_close(code, beast::bind_front_handler(&SessionOwnerBase::onClosed, shared_from_this()));
    }

    void onReadCB(beast::error_code e, size_t)
    {
        onRead(e, m_ws.got_text());
    }

    void doRead() override final
    {
        m_ws.async_read(m_readBuf, beast::bind_front_handler(&SessionOwnerT::onReadCB, shared_from_base()));
    }

    void doWrite(bool text, net::const_buffer buf) override final
    {
        m_ws.text(text);
        m_ws.async_write(buf, beast::bind_front_handler(&SessionOwnerBase::onWrite, shared_from_this()));
    }

    // accept flow
    void acceptUpgrade() override final
    {
        m_ws.async_accept(m_upgradeRequest,
            beast::bind_front_handler(&SessionOwnerBase::onConnectionEstablished, shared_from_this()));
    }

    // connect flow
    void connect(tcp::endpoint endpoint) override final
    {
        beast::get_lowest_layer(m_ws).async_connect(endpoint,
            beast::bind_front_handler(&SessionOwnerT::onConnectCB, shared_from_base()));
    }

    virtual void onConnectCB(beast::error_code e) = 0;

    void onReadyForWSHandshake(beast::error_code e)
    {
        if (e) return failed(e, "ws connect");

        setInitialClientOptions(m_session->getInitialOptions());

        m_ws.async_handshake(m_host, m_target,
            beast::bind_front_handler(&SessionOwnerBase::onConnectionEstablished, shared_from_this()));
    }

    // util
    WebSocketEndpointInfo getEndpointInfo() override final
    {
        // if we end-up requesting tje enpoint info on a disconnected socket just return a default value
        return getEndpointInfoOf(m_ws).value_or(WebSocketEndpointInfo{});
    }

    void setInitialServerOptions(WebSocketSessionOptions opts) override final
    {
        m_ws.read_message_max(opts.maxIncomingMessageSize.value_or(16 * 1024 * 1024));

        using bsb = websocket::stream_base;
        auto timeout = bsb::timeout::suggested(beast::role_type::server);
        if (opts.idleTimeout) timeout.idle_timeout = *opts.idleTimeout;
        m_ws.set_option(timeout);

        auto id = opts.hostId.value_or(
            std::string("fishnets-ws-server ") + BOOST_BEAST_VERSION_STRING
        );
        m_ws.set_option(bsb::decorator([id = std::move(id)](websocket::response_type& res) {
            res.set(http::field::server, id);
        }));

        resetHeartbeatTimer(opts.heartbeatInterval);
    }

    void setInitialClientOptions(WebSocketSessionOptions opts) override final
    {
        m_ws.read_message_max(opts.maxIncomingMessageSize.value_or(2 * 1024 * 1024));

        using bsb = websocket::stream_base;
        auto timeout = bsb::timeout::suggested(beast::role_type::client);
        if (opts.idleTimeout) timeout.idle_timeout = *opts.idleTimeout;
        m_ws.set_option(timeout);

        auto id = opts.hostId.value_or(
            std::string("fishnets-ws-client ") + BOOST_BEAST_VERSION_STRING
        );
        m_ws.set_option(bsb::decorator([id = std::move(id)](websocket::request_type& req) {
            req.set(http::field::user_agent, id);
        }));

        resetHeartbeatTimer(opts.heartbeatInterval);
    }

    void setOptions(const WebSocketSessionOptions& opts) final override
    {
        // ignore hostId, as it's only valid when connecting

        if (opts.maxIncomingMessageSize)
        {
            m_ws.read_message_max(*opts.maxIncomingMessageSize);
        }

        if (opts.idleTimeout)
        {
            websocket::stream_base::timeout t;
            m_ws.get_option(t);
            t.idle_timeout = *opts.idleTimeout;
            m_ws.set_option(t);
        }

        if (opts.heartbeatInterval)
        {
            resetHeartbeatTimer(opts.heartbeatInterval);
        }
    }
};

///////////////////////////////////////////////////////////////////////////////
// session owners

///////////////////////////////////////////////////////////////////////////////
// http session owner

using WSWS = websocket::stream<tcp::socket>;
class SessionOwnerWS final : public SessionOwnerT<WSWS>
{
public:
    using Super = SessionOwnerT<WSWS>;

    SessionOwnerWS(tcp::socket&& socket)
        : Super(WSWS(std::move(socket)))
    {}

    SessionOwnerWS(net::io_context& ctx)
        //: Super(WSWS(net::io_context::strand(ctx)))
        : Super(WSWS(ctx))
    {}

    // accept flow
    void accept() override
    {
        // read upgrade request to accept
        http::async_read(m_ws.next_layer(), m_readBuf, m_upgradeRequest,
            beast::bind_front_handler(&SessionOwnerBase::onUpgradeRequest, shared_from_this()));
    }

    // connect flow
    void onConnectCB(beast::error_code e) override
    {
        onReadyForWSHandshake(e);
    }
};

} // anonymous namespace

///////////////////////////////////////////////////////////////////////////////
// server

class Server
{
public:
    Server(WebSocketSessionFactoryFunc sessionFactory, tcp::endpoint endpoint, int numThreads)
        : m_ctx(numThreads)
        , m_acceptor(m_ctx, endpoint)
        , m_sessionFactory(std::move(sessionFactory))
    {
        doAccept();
        m_threads.reserve(size_t(numThreads));
        for (int i = 0; i < numThreads; ++i)
        {
            m_threads.emplace_back([this]() { m_ctx.run(); });
        }
    }

    ~Server()
    {
        m_ctx.stop();
        for (auto& thread : m_threads)
        {
            thread.join();
        }
    }

    void doAccept()
    {
        m_acceptor.async_accept(net::make_strand(m_ctx), beast::bind_front_handler(&Server::onAccept, this));
    }

    void onAccept(beast::error_code e, tcp::socket socket)
    {
        if (e)
        {
            std::cerr << "onAccept error: " << e << '\n';
            return;
        }

        // init session and owner
        auto ep = getEndpointInfoOf(socket);
        if (!ep)
        {
            std::cerr << "socket disconnected while accepting\n";
            return;
        }
        auto session = m_sessionFactory(*ep);
        if (!session)
        {
            std::cout << "session declined\n";
            doAccept();
            return;
        }

        std::shared_ptr<SessionOwnerBase> owner;
        owner = std::make_shared<SessionOwnerWS>(std::move(socket));
        owner->setInitialServerOptions(session->getInitialOptions());
        session->m_ioExecutorHolder = std::make_unique<ExecutorHolder>(owner->executor(), session);
        owner->setSession(std::move(session));

        // and initiate
        owner->accept();

        // accept more sessions
        doAccept();
    }

    net::io_context m_ctx;

    tcp::acceptor m_acceptor;

    std::vector<std::thread> m_threads;

    WebSocketSessionFactoryFunc m_sessionFactory;
};

WebSocketServer::WebSocketServer(WebSocketSessionFactoryFunc sessionFactory, uint16_t port, int numThreads)
{
    auto const address = tcp::v4();
    m_server.reset(new Server(std::move(sessionFactory), tcp::endpoint(address, port), numThreads));
}

WebSocketServer::~WebSocketServer() = default;

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

struct ReceiverSession final : public WebSocketSession
{};

WebSocketSessionPtr Make_ReceiverSession(const WebSocketEndpointInfo&)
{
    return std::make_shared<ReceiverSession>();
}

int main()
{
    WebSocketServer server(Make_ReceiverSession, 7654, 2);
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