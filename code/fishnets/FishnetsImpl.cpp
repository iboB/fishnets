// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#include "WebSocketClient.hpp"
#include "WebSocketClientSSLSettings.hpp"
#include "WebSocketServer.hpp"
#include "WebSocketServerSSLSettings.hpp"

#include "WebSocketSession.hpp"
#include "WebSocketSessionOptions.hpp"
#include "WebSocketEndpointInfo.hpp"

#define BOOST_BEAST_USE_STD_STRING_VIEW 1
#define BOOST_ASIO_USE_TS_EXECUTOR_AS_DEFAULT 1

#if defined(_MSC_VER)
#   pragma warning (disable: 4100)
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>

#if !defined(FISHNETS_ENABLE_SSL)
#   define FISHNETS_ENABLE_SSL 1
#endif

#if FISHNETS_ENABLE_SSL
#include <boost/beast/ssl.hpp>
#endif

#include <iostream>
#include <cassert>
#include <vector>
#include <thread>
#include <charconv>

namespace net = boost::asio;
namespace beast = boost::beast;
using tcp = net::ip::tcp;

namespace fishnets
{

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

    // connect flow

    virtual void connect(tcp::endpoint endpoint) = 0;

    // connections

    virtual void doClose(beast::websocket::close_code code) = 0;

    void onClosed(beast::error_code e)
    {
        if (e) return failed(e, "close");
    }

    void onConnectionEstablished(beast::error_code e)
    {
        if (e) return failed(e, "establish");

        m_session->opened(*this);

        doRead();
    }

    // io

    virtual void doRead() = 0;
    void onRead(beast::error_code e, bool text)
    {
        if (e == beast::websocket::error::closed) return closed();
        if (e) return failed(e, "read");

        auto bufData = m_readBuf.data().data();
        if (text)
        {
            m_session->wsReceivedText(itlib::make_memory_view(static_cast<char*>(bufData), m_readBuf.size()));
        }
        else
        {
            m_session->wsReceivedBinary(itlib::make_memory_view(static_cast<uint8_t*>(bufData), m_readBuf.size()));
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

    beast::flat_buffer m_readBuf;
    WebSocketSessionPtr m_sessionPayload;
    WebSocketSession* m_session = nullptr; // quick access pointer

    // only relevant when connecting
    std::string m_host;

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

void WebSocketSession::wsClose()
{
    if (!m_owner) return; // already closed
    m_owner->doClose(beast::websocket::close_code::normal);
}

void WebSocketSession::wsSend(itlib::const_memory_view<uint8_t> binary)
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

namespace
{

template <typename Socket>
WebSocketEndpointInfo getEndpointInfoOf(const Socket& s)
{
    auto ep = beast::get_lowest_layer(s).remote_endpoint();

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

    void doClose(beast::websocket::close_code code) override final
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

        m_ws.async_handshake(m_host, "/",
            beast::bind_front_handler(&SessionOwnerBase::onConnectionEstablished, shared_from_this()));
    }

    // util
    WebSocketEndpointInfo getEndpointInfo() override final
    {
        return getEndpointInfoOf(m_ws);
    }

    void setInitialServerOptions(WebSocketSessionOptions opts) override final
    {
        m_ws.read_message_max(opts.maxIncomingMessageSize.value_or(16*1024*1024));

        using bsb = beast::websocket::stream_base;
        auto timeout = bsb::timeout::suggested(beast::role_type::server);
        if (opts.idleTimeout) timeout.idle_timeout = *opts.idleTimeout;
        m_ws.set_option(timeout);

        auto id = opts.hostId.value_or(
            std::string("fishnets-ws-server ") + BOOST_BEAST_VERSION_STRING
        );
        m_ws.set_option(bsb::decorator([id = std::move(id)](beast::websocket::response_type& res) {
            res.set(beast::http::field::server, id);
        }));
    }

    void setInitialClientOptions(WebSocketSessionOptions opts) override final
    {
        m_ws.read_message_max(opts.maxIncomingMessageSize.value_or(2*1024*1024));

        using bsb = beast::websocket::stream_base;
        auto timeout = bsb::timeout::suggested(beast::role_type::client);
        if (opts.idleTimeout) timeout.idle_timeout = *opts.idleTimeout;
        m_ws.set_option(timeout);

        auto id = opts.hostId.value_or(
            std::string("fishnets-ws-client ") + BOOST_BEAST_VERSION_STRING
        );
        m_ws.set_option(bsb::decorator([id = std::move(id)](beast::websocket::request_type& req) {
            req.set(beast::http::field::user_agent, id);
        }));
    }

    void setOptions(const WebSocketSessionOptions& opts) final override
    {
        if (opts.maxIncomingMessageSize)
        {
            m_ws.read_message_max(*opts.maxIncomingMessageSize);
        }

        if (opts.idleTimeout)
        {
            beast::websocket::stream_base::timeout t;
            m_ws.get_option(t);
            t.idle_timeout = *opts.idleTimeout;
            m_ws.set_option(t);
        }

        // ignore id, as it's only valid when connecting
    }
};

///////////////////////////////////////////////////////////////////////////////
// session owners

///////////////////////////////////////////////////////////////////////////////
// http session owner

using WSWS = beast::websocket::stream<tcp::socket>;
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
        m_ws.async_accept(beast::bind_front_handler(&SessionOwnerBase::onConnectionEstablished, shared_from_this()));
    }

    // connect flow
    void onConnectCB(beast::error_code e) override
    {
        onReadyForWSHandshake(e);
    }
};

///////////////////////////////////////////////////////////////////////////////
// https session owner

#if FISHNETS_ENABLE_SSL

using WSSSL = beast::websocket::stream<net::ssl::stream<tcp::socket>>;
class SessionOwnerSSL final : public SessionOwnerT<WSSSL>
{
public:
    using Super = SessionOwnerT<WSSSL>;

    SessionOwnerSSL(tcp::socket&& socket, net::ssl::context& sslCtx)
        : Super(WSSSL(std::move(socket), sslCtx))
    {}

    SessionOwnerSSL(net::io_context& ctx, net::ssl::context& sslCtx)
        //: Super(WSSSL(net::io_context::strand(ctx), sslCtx))
        : Super(WSSSL(ctx, sslCtx))
    {}

    std::shared_ptr<SessionOwnerSSL> shared_from_base()
    {
        return std::static_pointer_cast<SessionOwnerSSL>(shared_from_this());
    }

    // accept flow
    void accept() override
    {
        m_ws.next_layer().async_handshake(net::ssl::stream_base::server,
            beast::bind_front_handler(&SessionOwnerSSL::onAcceptHandshake, shared_from_base()));
    }

    void onAcceptHandshake(beast::error_code e)
    {
        if (e) return failed(e, "accept");
        m_ws.async_accept(beast::bind_front_handler(&SessionOwnerBase::onConnectionEstablished, shared_from_this()));
    }

    // connect flow
    void onConnectCB(beast::error_code e) override
    {
        if (e) return failed(e, "connect");

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(!SSL_set_tlsext_host_name(m_ws.next_layer().native_handle(), m_host.c_str()))
        {
            e = beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
            return failed(e, "connect");
        }

        m_ws.next_layer().async_handshake(net::ssl::stream_base::client,
            beast::bind_front_handler(&SessionOwnerSSL::onReadyForWSHandshake, shared_from_base()));
    }
};

#endif

} // anonymous namespace

///////////////////////////////////////////////////////////////////////////////
// client

WebSocketClient::WebSocketClient(WebSocketSessionPtr session, const std::string& addr, uint16_t port, WebSocketClientSSLSettings* sslSettings)
{
    if (!session) return;

    net::io_context ctx(1);
#if FISHNETS_ENABLE_SSL
    std::unique_ptr<net::ssl::context> sslCtx;
#endif

    {
        // tcp::resolver resolver{net::io_context::strand(ctx)};
        tcp::resolver resolver{ctx};

        char portstr[6] = {};
        std::to_chars(portstr, portstr+6, port);
        auto results = resolver.resolve(tcp::v4(), addr, portstr);
        if (results.empty())
        {
            std::cerr << "Could not resolve " << addr << '\n';
            return;
        }

        // init session and owner
        std::shared_ptr<SessionOwnerBase> owner;
        if (sslSettings)
        {
#if FISHNETS_ENABLE_SSL
            sslCtx.reset(new net::ssl::context(net::ssl::context::tlsv12_client));
            boost::system::error_code ec;
            for (auto& cert : sslSettings->customCertificates)
            {
                sslCtx->add_certificate_authority(boost::asio::buffer(cert), ec);
                if (ec) break;
            }
            if (ec)
            {
                std::cerr << "Could not load custom certificates: " << ec.message() << '\n';
                return;
            }
            owner = std::make_shared<SessionOwnerSSL>(ctx, *sslCtx);
#else
            std::terminate();
#endif
        }
        else
        {
            owner = std::make_shared<SessionOwnerWS>(ctx);
        }
        session->m_ioExecutorHolder = std::make_unique<ExecutorHolder>(ctx.get_executor(), session);
        owner->setSession(std::move(session));

        // and initiate
        owner->m_host = addr;
        owner->m_host += ':';
        owner->m_host += portstr;
        owner->connect(results.begin()->endpoint());
    }

    ctx.run();
}

///////////////////////////////////////////////////////////////////////////////
// server

class Server
{
public:
    Server(WebSocketSessionFactoryFunc sessionFactory, tcp::endpoint endpoint, int numThreads, WebSocketServerSSLSettings* sslSettings)
        : m_ctx(numThreads)
        , m_acceptor(m_ctx, endpoint)
        , m_sessionFactory(std::move(sessionFactory))
    {
        if (sslSettings)
        {
#if FISHNETS_ENABLE_SSL
            m_sslSettings = *sslSettings;

            m_sslCtx.reset(new net::ssl::context(net::ssl::context::tlsv12));
            m_sslCtx->set_options(
                net::ssl::context::default_workarounds |
                net::ssl::context::no_sslv2 |
                net::ssl::context::single_dh_use);

            if (m_sslSettings.certificate.empty())
                m_sslCtx->use_certificate_chain_file(m_sslSettings.certificateFile);
            else
                m_sslCtx->use_certificate_chain(net::buffer(m_sslSettings.certificate));

            if (m_sslSettings.privateKey.empty())
                m_sslCtx->use_private_key_file(m_sslSettings.privateKeyFile, net::ssl::context::file_format::pem);
            else
                m_sslCtx->use_private_key(net::buffer(m_sslSettings.privateKey), net::ssl::context::file_format::pem);

            if (m_sslSettings.tmpDH.empty())
                m_sslCtx->use_tmp_dh_file(m_sslSettings.tmpDHFile);
            else
                m_sslCtx->use_tmp_dh(net::buffer(m_sslSettings.tmpDH));
#else
            std::terminate();
#endif
        }

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
        auto session = m_sessionFactory(getEndpointInfoOf(socket));
        if (!session)
        {
            std::cout << "session declined\n";
            doAccept();
            return;
        }

        std::shared_ptr<SessionOwnerBase> owner;
#if FISHNETS_ENABLE_SSL
        if (m_sslCtx)
        {

            owner = std::make_shared<SessionOwnerSSL>(std::move(socket), *m_sslCtx);
        }
        else
#endif
        {
            owner = std::make_shared<SessionOwnerWS>(std::move(socket));
        }
        owner->setInitialServerOptions(session->getInitialOptions());
        session->m_ioExecutorHolder = std::make_unique<ExecutorHolder>(owner->executor(), session);
        owner->setSession(std::move(session));

        // and initiate
        owner->accept();

        // accept more sessions
        doAccept();
    }

    net::io_context m_ctx;
#if FISHNETS_ENABLE_SSL
    std::unique_ptr<net::ssl::context> m_sslCtx;
#endif

    tcp::acceptor m_acceptor;

    std::vector<std::thread> m_threads;

    WebSocketSessionFactoryFunc m_sessionFactory;

    // only used for https
    // here we persist the strings provided by the user
    WebSocketServerSSLSettings m_sslSettings;
};

WebSocketServer::WebSocketServer(WebSocketSessionFactoryFunc sessionFactory, uint16_t port, int numThreads, WebSocketServerSSLSettings* sslSettings)
{
    auto const address = tcp::v4();
    m_server.reset(new Server(std::move(sessionFactory), tcp::endpoint(address, port), numThreads, sslSettings));
}

WebSocketServer::~WebSocketServer() = default;

} // namespace fishnets
