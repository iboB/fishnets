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
#include <charconv>
#include <unordered_map>

#if !defined(FISHNETS_ENABLE_SSL)
#   define FISHNETS_ENABLE_SSL 1
#endif

#if FISHNETS_ENABLE_SSL
#include <boost/beast/ssl.hpp>
#include "SslContext.hpp"
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
    : m_impl(itlib::make_unique(Impl{net::make_work_guard(ctx.impl().ctx.get_executor())}))
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

#if FISHNETS_ENABLE_SSL
struct SslContext::Impl {
    Impl() : ctx(ssl::context::tlsv12) {}

    net::const_buffer addString(std::string& str) {
        const auto& own = strings.emplace_back(std::move(str));
        return net::buffer(own);
    }

    std::list<std::string> strings;
    ssl::context ctx;
};

SslContext::SslContext() : m_impl(itlib::make_unique(Impl{})) {}
SslContext::~SslContext() = default;

void SslContext::useCertificateChain(std::string certificate) {
    m_impl->ctx.use_certificate_chain(m_impl->addString(certificate));
}
void SslContext::useCertificateChainFile(std::string certificateFile) {
    m_impl->ctx.use_certificate_chain_file(certificateFile);
}
void SslContext::usePrivateKey(std::string privateKey) {
    m_impl->ctx.use_private_key(m_impl->addString(privateKey), ssl::context::file_format::pem);
}
void SslContext::usePrivateKeyFile(std::string privateKeyFile) {
    m_impl->ctx.use_private_key_file(privateKeyFile, ssl::context::file_format::pem);
}
void SslContext::useTmpDh(std::string tmpDh) {
    m_impl->ctx.use_tmp_dh(m_impl->addString(tmpDh));
}
void SslContext::useTmpDhFile(std::string tmpDhFile) {
    m_impl->ctx.use_tmp_dh_file(tmpDhFile);
}
bool SslContext::addCertificateAuthority(std::string ca) {
    beast::error_code ec;
    m_impl->ctx.add_certificate_authority(m_impl->addString(ca), ec);
    if (ec) {
        std::cerr << "Could not load custom certificates: " << ec.message() << '\n';
        return false;
    }
    return true;
}

using RawWsSsl = ws::stream<ssl::stream<tcp::socket>>;
#endif

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

struct BasicConnector : public itlib::enable_shared_from {
    WsConnectionHandlerPtr m_handler;
    void failed(beast::error_code e, std::string_view where) {
        auto msg = std::string(where);
        msg += ": ";
        msg += e.message();
        m_handler->onConnectionError(msg);
    }
protected:
    ~BasicConnector() = default;
};

struct ServerConnector : public BasicConnector {
    beast::flat_buffer m_readBuf;
    http::request<http::string_body> m_upgradeRequest;

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
protected:
    ~ServerConnector() = default;
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

struct WsServer : public itlib::enable_shared_from {
    net::io_context& m_ctx;
    WsServerConnectionHandlerFactory m_factory;

    tcp::acceptor m_acceptor;

    SslContext* m_sslCtx = nullptr;

    WsServer(
        net::io_context& ctx,
        WsServerConnectionHandlerFactory factory,
        const tcp::endpoint& endpoint,
        SslContext* sslCtx
    )
        : m_ctx(ctx)
        , m_factory(std::move(factory))
        , m_acceptor(ctx, endpoint)
        , m_sslCtx(sslCtx)
    {}

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
            con = std::make_shared<ServerConnectorSsl>(RawWsSsl(std::move(socket), m_sslCtx->impl().ctx));
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

struct ClientConnector : public BasicConnector {
    std::string m_host;
    std::string m_target;

    virtual void connect(tcp::endpoint endpoint) = 0;
protected:
    ~ClientConnector() = default;
};

template <typename RawSocket>
struct ClientConnectorT : public ClientConnector {
    RawSocket m_ws;

    ClientConnectorT(RawSocket&& ws) : m_ws(std::move(ws)) {}

    void connect(tcp::endpoint endpoint) override final
    {
        beast::get_lowest_layer(m_ws).async_connect(endpoint,
            beast::bind_front_handler(&ClientConnectorT::onConnect, shared_from(this)));
    }

    virtual void onConnect(beast::error_code e) = 0;

    void onReadyForWSHandshake(beast::error_code e)
    {
        if (e) return failed(e, "ws connect");

        //setInitialClientOptions(m_session->getInitialOptions());

        m_ws.async_handshake(m_host, m_target,
            beast::bind_front_handler(&ClientConnectorT::onConnectionEstablished, shared_from(this)));
    }

    void onConnectionEstablished(beast::error_code e) {
        if (e) return failed(e, "establish");
        m_handler->onConnected(
            WebSocket(std::make_unique<WebSocketImplT<RawSocket>>(std::move(m_ws))),
            m_target
        );
    }
};

struct ClientConnectorWs final : public ClientConnectorT<RawWs> {
    using ClientConnectorT<RawWs>::ClientConnectorT;
    void onConnect(beast::error_code e) override {
        onReadyForWSHandshake(e);
    }
};

#if FISHNETS_ENABLE_SSL
struct ClientConnectorSsl final : public ClientConnectorT<RawWsSsl> {
    using ClientConnectorT<RawWsSsl>::ClientConnectorT;
    void onConnect(beast::error_code e) override {
        if (e) return failed(e, "connect");

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(m_ws.next_layer().native_handle(), m_host.c_str()))
        {
            e = beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
            return failed(e, "connect");
        }

        m_ws.next_layer().async_handshake(ssl::stream_base::client,
            beast::bind_front_handler(&ClientConnectorSsl::onReadyForWSHandshake, shared_from(this)));
    }
};
#endif

} // namespace

void Context::wsServe(const EndpointInfo& endpoint, WsServerConnectionHandlerFactory factory, SslContext* ssl) {
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

void Context_wsConnect(
    Context& self,
    WsConnectionHandlerPtr& handler,
    tcp::endpoint ep,
    std::string host,
    std::string_view target,
    SslContext* ssl
) {
    std::shared_ptr<ClientConnector> con;

#if FISHNETS_ENABLE_SSL
    if (ssl) {
        con = std::make_shared<ClientConnectorSsl>(RawWsSsl(self.impl().ctx, ssl->impl().ctx));
    }
    else
#endif
    {
        con = std::make_shared<ClientConnectorWs>(RawWs(self.impl().ctx));
    }

    con->m_handler = std::move(handler);

    con->m_host = std::move(host);
    if (target.empty()) target = "/";
    con->m_target = std::string(target);

    con->connect(std::move(ep));
}

void Context::wsConnect(
    WsConnectionHandlerPtr handler,
    const EndpointInfo& endpoint,
    std::string_view target,
    SslContext* ssl
) {
    Context_wsConnect(
        *this,
        handler,
        tcp::endpoint(net::ip::make_address(endpoint.address), endpoint.port),
        endpoint.address + ':' + std::to_string(endpoint.port),
        target,
        ssl
    );
}

void Context::wsConnect(WsConnectionHandlerPtr handler, std::string_view host, SslContext* sslCtx) {

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
