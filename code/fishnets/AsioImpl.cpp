// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsSessionOptions.hpp"
#include "Context.hpp"
#include "ContextWorkGuard.hpp"
#include "WebSocket.hpp"
#include "WsConnectionHandler.hpp"

#define BOOST_BEAST_USE_STD_STRING_VIEW 1

#if defined(_MSC_VER)
#   pragma warning (disable: 4100)
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>

#include <itlib/make_ptr.hpp>
#include <itlib/shared_from.hpp>

#include <iostream>

#if !defined(FISHNETS_ENABLE_SSL)
#   define FISHNETS_ENABLE_SSL 1
#endif

#if FISHNETS_ENABLE_SSL
#include <boost/beast/ssl.hpp>
#include "ServerSslSettings.hpp"
#include "ClientSslSettings.hpp"
#endif

namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace ws = beast::websocket;
namespace http = beast::http;
using tcp = net::ip::tcp;

namespace fishnets {

struct ContextWorkGuard::Impl {
    net::executor_work_guard<net::io_context::executor_type> guard;
};

struct Context::Impl {
    net::io_context ctx;
};

ContextWorkGuard::ContextWorkGuard() = default;
ContextWorkGuard::ContextWorkGuard(Context& ctx)
    : m_impl(itlib::make_unique(Impl{net::make_work_guard(ctx.m_impl->ctx.get_executor())}))
{}
ContextWorkGuard::~ContextWorkGuard() = default;

ContextWorkGuard::ContextWorkGuard(ContextWorkGuard&&) noexcept = default;
ContextWorkGuard& ContextWorkGuard::operator=(ContextWorkGuard&&) noexcept = default;

void ContextWorkGuard::reset() {
    m_impl.reset();
}

Context::Context()
    : m_impl(std::make_unique<Impl>())
{}

Context::~Context() = default;

void Context::run() {
    m_impl->ctx.run();
}

void Context::stop() {
    m_impl->ctx.stop();
}

bool Context::stopped() const {
    return m_impl->ctx.stopped();
}

void Context::restart() {
    m_impl->ctx.restart();
}

ContextWorkGuard Context::makeWorkGuard() {
    return ContextWorkGuard(*this);
}

using RawWs = ws::stream<tcp::socket>;
using RawWsSsl = ws::stream<ssl::stream<tcp::socket>>;

struct WebSocket::Impl {
public:
    virtual ~Impl() = default;

    beast::flat_buffer m_readBuf;
    ByteSpan m_userBuf;

    void startTimer(uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb);

    void cancelTimer(uint64_t id);
    void cancelAllTimers();

    bool connected() const;

    void recv(ByteSpan buf, RecvCb cb);

    void send(Packet buf, SendCb cb);

    void close(CloseCb cb);

    EndpointInfo getEndpointInfo() const;
};

namespace {

template <typename Socket>
std::optional<EndpointInfo> getEndpointInfoOf(const Socket& s) {
    beast::error_code err;
    auto ep = beast::get_lowest_layer(s).remote_endpoint(err);
    // if there's an error, the socket has likely been disconnected
    if (err) return {};

    EndpointInfo ret;
    ret.address = ep.address().to_string();
    ret.port = ep.port();
    return ret;
}

template <typename RawSocket>
struct WebSocketImplT final : public WebSocket::Impl {
    RawSocket m_ws;

    WebSocketImplT(RawSocket&& ws)
        : m_ws(std::move(ws))
    {}
};

struct ServerConnector : public itlib::enable_shared_from {
    WsConnectionHandlerPtr m_handler;
    beast::flat_buffer m_readBuf;
    http::request<http::string_body> m_upgradeRequest;

    void failed(beast::error_code e, std::string_view where) {
        auto msg = std::string(where);
        msg += ": ";
        msg += e.message();
        m_handler->onConnectionError(msg);
    }

    virtual void accept() = 0;

    void onUpgradeRequest(beast::error_code e, size_t /*bytesTransfered*/)
    {
        if (e) return failed(e, "upgrade");
        if (!ws::is_upgrade(m_upgradeRequest)) {
            return failed(ws::error::no_connection_upgrade, "upgrade");
        }
        acceptUpgrade();
    }

    virtual void acceptUpgrade() = 0;
};

template <typename RawSocket>
struct ServerConnectorT : public ServerConnector {
    RawSocket m_ws;

    ServerConnectorT(RawSocket&& ws)
        : m_ws(std::move(ws))
    {}

    void acceptUpgrade() override final {
        m_ws.async_accept(m_upgradeRequest,
            beast::bind_front_handler(&ServerConnectorT::onConnectionEstablished, shared_from(this)));
    }

    void onConnectionEstablished(beast::error_code e) {
        if (e) return failed(e, "accept");
        m_handler->onConnected(
            WebSocket(std::make_unique<WebSocketImplT<RawSocket>>(std::move(m_ws))),
            m_upgradeRequest.target()
        );
    }
};

struct ServerConnectorWs final : public ServerConnectorT<RawWs> {
    using ServerConnectorT<RawWs>::ServerConnectorT;

    void accept() override {
        // read upgrade request to accept
        http::async_read(m_ws.next_layer(), m_readBuf, m_upgradeRequest,
            beast::bind_front_handler(&ServerConnector::onUpgradeRequest, shared_from(this)));
    }
};

#if FISHNETS_ENABLE_SSL
struct ServerConnectorSsl final : public ServerConnectorT<RawWsSsl> {
    using ServerConnectorT<RawWsSsl>::ServerConnectorT;

    void accept() override {
        m_ws.next_layer().async_handshake(ssl::stream_base::server,
            beast::bind_front_handler(&ServerConnectorSsl::onAcceptHandshake, shared_from(this)));
    }

    void onAcceptHandshake(beast::error_code e) {
        if (e) return failed(e, "accept");
        // read upgrade request to accept
        http::async_read(m_ws.next_layer(), m_readBuf, m_upgradeRequest,
            beast::bind_front_handler(&ServerConnector::onUpgradeRequest, shared_from(this)));
    }
};
#endif

} // namespace

namespace {
struct WsServer : public itlib::enable_shared_from {
    net::io_context& m_ctx;
    WsServerConnectionHandlerFactory m_factory;

    tcp::acceptor m_acceptor;

#if FISHNETS_ENABLE_SSL
    std::unique_ptr<ssl::context> m_sslCtx;
    ServerSslSettings m_sslSettings; // here we persist the strings provided by the user
#endif

    WsServer(
        net::io_context& ctx,
        WsServerConnectionHandlerFactory factory,
        const tcp::endpoint& endpoint,
        const ServerSslSettings* sslSettings
    )
        : m_ctx(ctx)
        , m_factory(std::move(factory))
        , m_acceptor(ctx, endpoint)
    {
        if (sslSettings) {
#if FISHNETS_ENABLE_SSL
            m_sslSettings = *sslSettings;
            m_sslCtx.reset(new ssl::context(ssl::context::tlsv12));

            if (m_sslSettings.certificate.empty())
                m_sslCtx->use_certificate_chain_file(m_sslSettings.certificateFile);
            else
                m_sslCtx->use_certificate_chain(net::buffer(m_sslSettings.certificate));

            if (m_sslSettings.privateKey.empty())
                m_sslCtx->use_private_key_file(m_sslSettings.privateKeyFile, ssl::context::file_format::pem);
            else
                m_sslCtx->use_private_key(net::buffer(m_sslSettings.privateKey), ssl::context::file_format::pem);

            if (m_sslSettings.tmpDH.empty())
                m_sslCtx->use_tmp_dh_file(m_sslSettings.tmpDHFile);
            else
                m_sslCtx->use_tmp_dh(net::buffer(m_sslSettings.tmpDH));
#else
            throw std::runtime_error("SSL is not enabled");
#endif
        }
    }

    void doAccept() {
        m_acceptor.async_accept(
            m_ctx.get_executor(),
            beast::bind_front_handler(&WsServer::onAccept, shared_from(this))
        );
    }

    void onAccept(beast::error_code e, tcp::socket socket) {
        if (e) {
            std::cerr << "onAccept error: " << e << '\n';
            return;
        }

        // init session handler
        auto ep = getEndpointInfoOf(socket);
        if (!ep) {
            std::cerr << "socket disconnected while accepting\n";
            return;
        }

        auto handler = m_factory(*ep);

        if (!handler) {
            std::cout << "session declined\n";
            doAccept();
            return;
        }

        std::shared_ptr<ServerConnector> con;

#if FISHNETS_ENABLE_SSL
        if (m_sslCtx) {

            con = std::make_shared<ServerConnectorSsl>(RawWsSsl(std::move(socket), *m_sslCtx));
        }
        else
#endif
        {
            con = std::make_shared<ServerConnectorWs>(RawWs(std::move(socket)));
        }

        // accept more sessions
        doAccept();
    }
};
} // namespace

void Context::wsServe(EndpointInfo endpoint, WsServerConnectionHandlerFactory factory, const ServerSslSettings* ssl) {
    auto ep = [&] {
        if (endpoint.address == IPv4) {
            return tcp::endpoint(tcp::v4(), endpoint.port);
        }
        else if (endpoint.address == IPv6) {
            return tcp::endpoint(tcp::v6(), endpoint.port);
        }
        else {
            return tcp::endpoint(net::ip::make_address(endpoint.address), endpoint.port);
        }
    }();

    auto server = std::make_shared<WsServer>(m_impl->ctx, std::move(factory), ep, ssl);
    server->doAccept();
}

void Context::wsConnect(EndpointInfo endpoint, WsConnectionHandlerPtr handler, const ClientSslSettings* ssl) {
}

WsConnectionHandler::~WsConnectionHandler() = default; // just export vtable

WebSocket::WebSocket(std::unique_ptr<Impl> impl) : m_impl(std::move(impl)) {}
WebSocket::~WebSocket() = default;
WebSocket::WebSocket(WebSocket&&) noexcept = default;
WebSocket& WebSocket::operator=(WebSocket&&) noexcept = default;
void WebSocket::startTimer(uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb) {
    m_impl->startTimer(id, timeFromNow, std::move(cb));
}
void WebSocket::cancelTimer(uint64_t id) { m_impl->cancelTimer(id); }
void WebSocket::cancelAllTimers() { m_impl->cancelAllTimers(); }
bool WebSocket::connected() const { return m_impl->connected(); }
void WebSocket::recv(ByteSpan buf, RecvCb cb) { m_impl->recv(buf, std::move(cb)); }
void WebSocket::send(Packet buf, SendCb cb) { m_impl->send(buf, std::move(cb)); }
void WebSocket::close(CloseCb cb) { m_impl->close(std::move(cb)); }
EndpointInfo WebSocket::getEndpointInfo() const { return m_impl->getEndpointInfo(); }

} // namespace fishnets
