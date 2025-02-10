// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsSessionOptions.hpp"
#include "Context.hpp"
#include "ContextWorkGuard.hpp"
#include "WebSocket.hpp"
#include "WsConnectionHandler.hpp"
#include "Task.hpp"

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
#include <unordered_map>

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

class Executor {
public:
    net::any_io_executor ex;
};

struct WebSocket::Impl {
public:
    virtual ~Impl() = default;

    beast::flat_buffer m_growableBuf;
    ByteSpan m_userBuf;

    ExecutorPtr m_executor;

    std::unordered_map<uint64_t, net::steady_timer> m_timers;

    void startTimer(uint64_t id, std::chrono::milliseconds timeFromNow, TimerCb cb) {
        auto& timer = [&]() -> net::steady_timer& {
            auto [it, _] = m_timers.try_emplace(id, m_executor->ex);
            return it->second;
        }();
        timer.expires_after(timeFromNow);
        timer.async_wait([this, id, cb = std::move(cb)](beast::error_code e) {
            if (e == net::error::operation_aborted) {
                cb(id, true);
            }
            else {
                cb(id, false);
            }
        });
    }

    void cancelTimer(uint64_t id) {
        auto it = m_timers.find(id);
        if (it != m_timers.end()) {
            it->second.cancel();
            m_timers.erase(it);
        }
    }

    void cancelAllTimers() {
        for (auto& t : m_timers) {
            t.second.cancel();
        }
        m_timers.clear();
    }

    virtual bool connected() const = 0;

    virtual void recv(ByteSpan span, RecvCb cb) = 0;

    virtual void send(ConstPacket packet, SendCb cb) = 0;

    virtual void close(CloseCb cb) = 0;

    virtual EndpointInfo getEndpointInfo() const = 0;
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

    WebSocketImplT(RawSocket&& ws) : m_ws(std::move(ws)) {
        m_executor = itlib::make_shared(Executor{m_ws.get_executor()});
    }


    bool connected() const override {
        return m_ws.is_open();
    }

    void recv(WebSocket::ByteSpan span, WebSocket::RecvCb cb) override {
        m_userBuf = span;

        auto onRead = [this, cb = std::move(cb)](beast::error_code e, size_t size) {
            if (e) {
                cb(itlib::unexpected(e.message()));
                return;
            }

            WebSocket::Packet packet;
            if (m_userBuf.empty()) {
                WebSocket::ByteSpan span(static_cast<uint8_t*>(m_growableBuf.data().data()), m_growableBuf.size());
                packet.data = span;
            }
            else {
                packet.data = m_userBuf.subspan(0, size);
            }

            packet.complete = m_ws.is_message_done();
            packet.text = m_ws.got_text();

            cb(std::move(packet));

            m_growableBuf.clear();
            m_userBuf = {};
        };

        if (m_userBuf.empty()) {
            m_ws.async_read(m_growableBuf, std::move(onRead));
        }
        else {
            m_ws.async_read_some(net::buffer(m_userBuf.data(), m_userBuf.size()), std::move(onRead));
        }
    }

    void send(WebSocket::ConstPacket packet, WebSocket::SendCb cb) override {
        auto onWrite = [cb = std::move(cb)](beast::error_code e, size_t) {
            if (e) {
                cb(itlib::unexpected(e.message()));
            }
            else {
                cb({});
            }
        };

        m_ws.text(packet.text);
        m_ws.async_write_some(packet.complete, net::buffer(packet.data.data(), packet.data.size()), std::move(onWrite));
    }

    void close(WebSocket::CloseCb cb) override {
        m_ws.async_close(ws::close_code::normal, [cb = std::move(cb)](beast::error_code e) {
            if (e) {
                cb(itlib::unexpected(e.message()));
            }
            else {
                cb({});
            }
        });
    }

    EndpointInfo getEndpointInfo() const override {
        return getEndpointInfoOf(m_ws).value_or(EndpointInfo{});
    }
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
void WebSocket::recv(ByteSpan span, RecvCb cb) { m_impl->recv(span, std::move(cb)); }
void WebSocket::send(ConstPacket packet, SendCb cb) { m_impl->send(packet, std::move(cb)); }
void WebSocket::close(CloseCb cb) { m_impl->close(std::move(cb)); }
EndpointInfo WebSocket::getEndpointInfo() const { return m_impl->getEndpointInfo(); }
const ExecutorPtr& WebSocket::executor() const { return m_impl->m_executor; }

void post(Executor& e, Task task) {
    net::post(e.ex, std::move(task));
}

} // namespace fishnets
