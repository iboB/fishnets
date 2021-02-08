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

#define BOOST_BEAST_USE_STD_STRING_VIEW 1
#define BOOST_ASIO_USE_TS_EXECUTOR_AS_DEFAULT 1

#if defined(_MSC_VER)
#   pragma warning (disable: 4100)
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>

#define FISHNETS_ENABLE_SSL 0

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
    ExecutorHolder(net::executor&& ex)
        : executor(std::move(ex))
    {}
    net::executor executor;
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

        auto bufData = m_readBuf.cdata().data();
        if (text)
        {
            m_session->wsReceivedText(std::string_view(static_cast<const char*>(bufData), m_readBuf.size()));
        }
        else
        {
            m_session->wsReceivedBinary(itlib::make_memory_view(static_cast<const uint8_t*>(bufData), m_readBuf.size()));
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
    net::dispatch(m_ioExecutorHolder->executor, std::move(task));
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

namespace
{

template <typename WS>
void setCommonServerOptions(WS& ws)
{
    ws.read_message_max(32 * 1024 * 1024);

    ws.set_option(beast::websocket::stream_base::decorator([](beast::websocket::response_type& res) {
        res.set(beast::http::field::server, std::string(BOOST_BEAST_VERSION_STRING) + " ws-server");
    }));

    ws.set_option(beast::websocket::stream_base::timeout::suggested(beast::role_type::server));
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

        // Set suggested timeout settings for the websocket
        m_ws.set_option(beast::websocket::stream_base::timeout::suggested(beast::role_type::client));

        // Set a decorator to change the User-Agent of the handshake
        m_ws.set_option(beast::websocket::stream_base::decorator([](beast::websocket::request_type& req) {
            req.set(beast::http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING) + " ws-client");
        }));

        m_ws.async_handshake(m_host, "/",
            beast::bind_front_handler(&SessionOwnerBase::onConnectionEstablished, shared_from_this()));
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
    {
        setCommonServerOptions(m_ws);
    }

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
    {
        setCommonServerOptions(m_ws);
    }

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

        session->m_ioExecutorHolder = std::make_unique<ExecutorHolder>(ctx.get_executor());
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
        auto session = m_sessionFactory();
        session->m_ioExecutorHolder = std::make_unique<ExecutorHolder>(owner->executor());
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
