// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "Context.hpp"
#include "ContextWorkGuard.hpp"

#include "WebSocket.hpp"
#include "WsConnectionHandler.hpp"
#include "WsServerHandler.hpp"
#include "WebSocketOptions.hpp"

#include "HttpRequestHeader.hpp"
#include "HttpRequestBody.hpp"
#include "HttpResponseHandler.hpp"
#include "HttpRequestOptions.hpp"
#include "HttpResponseSocket.hpp"

#include "Post.hpp"
#include "Timer.hpp"

#define BOOST_BEAST_USE_STD_STRING_VIEW 1

#if defined(_MSC_VER)
#   pragma warning (disable: 4100)
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/strand.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/as_tuple.hpp>

#include <itlib/make_ptr.hpp>
#include <itlib/shared_from.hpp>

#include <furi/furi.hpp>

#include <unordered_map>
#include <cstdio>
#include <mutex>
#include <list>

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

struct Context::Impl {
    net::io_context ctx;
    void wsServe(std::span<const tcp::endpoint> eps, WsServerHandlerPtr handler, SslContext* ssl);

    tcp::resolver& get_resolver() {
        std::lock_guard lock(m_resolverMutex);
        if (!m_resolver) {
            m_resolver.emplace(ctx);
        }
        return *m_resolver;
    }
private:
    std::mutex m_resolverMutex;
    std::optional<tcp::resolver> m_resolver;
};

struct ContextWorkGuard::Impl {
    net::executor_work_guard<net::io_context::executor_type> guard;
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
void SslContext::addCertificateAuthority(std::string ca) {
    m_impl->ctx.add_certificate_authority(m_impl->addString(ca));
}

using RawWsSsl = ws::stream<ssl::stream<tcp::socket>>;
#endif

class Executor {
public:
    net::any_io_executor ex;
};

WebSocket::WebSocket() = default;
WebSocket::~WebSocket() = default;

struct WebSocketImpl : public WebSocket {
    using WebSocket::m_executor;

    beast::flat_buffer m_growableBuf;
    ByteSpan m_userBuf;
};

namespace {

tcp::endpoint EndpointInfo_toTcp(const EndpointInfo& ep) {
    if (ep.address == IPv4) {
        return tcp::endpoint(tcp::v4(), ep.port);
    }
    else if (ep.address == IPv6) {
        return tcp::endpoint(tcp::v6(), ep.port);
    }
    else {
        return tcp::endpoint(net::ip::make_address(ep.address), ep.port);
    }
}

std::vector<tcp::endpoint> EndpointInfo_toTcp(std::span<const EndpointInfo> span) {
    std::vector<tcp::endpoint> eps;
    eps.reserve(span.size());
    for (auto& e : span) {
        eps.push_back(EndpointInfo_toTcp(e));
    }
    return eps;
}

EndpointInfo EndpointInfo_fromTcp(const tcp::endpoint& ep) {
    EndpointInfo ret;
    ret.address = ep.address().to_string();
    ret.port = ep.port();
    return ret;
}

template <typename Socket>
std::optional<EndpointInfo> getEndpointInfoOf(const Socket& s) {
    beast::error_code err;
    auto ep = beast::get_lowest_layer(s).remote_endpoint(err);
    // if there's an error, the socket has likely been disconnected
    if (err) return {};

    return EndpointInfo_fromTcp(ep);
}

template <typename RawSocket>
struct WebSocketImplT final : public WebSocketImpl {
    RawSocket m_ws;

    explicit WebSocketImplT(RawSocket&& ws) : m_ws(std::move(ws)) {
        m_executor = itlib::make_shared(Executor{m_ws.get_executor()});
    }


    bool connected() const override {
        return m_ws.is_open();
    }

    void recv(WebSocket::ByteSpan span, WebSocket::RecvCb cb) override {
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

            m_userBuf = {};
        };

        m_userBuf = span;
        if (m_userBuf.empty()) {
            m_growableBuf.clear();
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

    void setOptions(const WebSocketOptions& opts) override {
        // ignore hostId, as it's only applicable when connecting

        if (opts.maxIncomingMessageSize) {
            m_ws.read_message_max(*opts.maxIncomingMessageSize);
        }

        if (opts.pongTimeout) {
            ws::stream_base::timeout t;
            m_ws.get_option(t);
            t.idle_timeout = *opts.pongTimeout;
            m_ws.set_option(t);
        }
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

    virtual void setInitialOptions(WebSocketOptions opts) = 0;

    virtual void accept() = 0;

    void onUpgradeRequest(beast::error_code e, size_t /*bytesTransfered*/) {
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

    explicit ServerConnectorT(RawSocket&& ws)
        : m_ws(std::move(ws))
    {}

    void setInitialOptions(WebSocketOptions opts) override final {
        m_ws.read_message_max(opts.maxIncomingMessageSize.value_or(16 * 1024 * 1024));

        using bsb = ws::stream_base;
        auto timeout = bsb::timeout::suggested(beast::role_type::server);
        if (opts.pongTimeout) timeout.idle_timeout = *opts.pongTimeout;
        m_ws.set_option(timeout);

        auto id = opts.hostId.value_or(
            std::string("fishnets-ws-server/") + BOOST_BEAST_VERSION_STRING
        );
        m_ws.set_option(bsb::decorator([id = std::move(id)](ws::response_type& res) {
            res.set(http::field::server, id);
        }));
    }

    void acceptUpgrade() override final {
        m_ws.async_accept(m_upgradeRequest,
            beast::bind_front_handler(&ServerConnectorT::onConnectionEstablished, shared_from(this)));
    }

    void onConnectionEstablished(beast::error_code e) {
        if (e) return failed(e, "accept");
        m_handler->onConnected(
            std::make_unique<WebSocketImplT<RawSocket>>(std::move(m_ws)),
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

struct ClientConnector : public BasicConnector {
    std::string m_host;
    std::string m_target;

    std::vector<tcp::endpoint> m_endpoints;

    void connect(std::vector<tcp::endpoint> endpoints) {
        m_endpoints = std::move(endpoints);
        doConnect();
    }

    virtual void doConnect() = 0;
protected:
    ~ClientConnector() = default;
};

template <typename RawSocket>
struct ClientConnectorT : public ClientConnector {
    RawSocket m_ws;

    explicit ClientConnectorT(RawSocket&& ws) : m_ws(std::move(ws)) {}

    void doConnect() override final {
        async_connect(beast::get_lowest_layer(m_ws), m_endpoints,
            beast::bind_front_handler(&ClientConnectorT::onConnect, shared_from(this)));
    }

    void onConnect(beast::error_code e, const tcp::endpoint& ep) {
        if (e) return failed(e, "connect");
        if (m_host.empty()) {
            m_host = ep.address().to_string();
        }
        handshake();
    }

    virtual void handshake() = 0;

    void setInitialOptions(WebSocketOptions opts) {
        m_ws.read_message_max(opts.maxIncomingMessageSize.value_or(2 * 1024 * 1024));

        using bsb = ws::stream_base;
        auto timeout = bsb::timeout::suggested(beast::role_type::client);
        if (opts.pongTimeout) timeout.idle_timeout = *opts.pongTimeout;
        m_ws.set_option(timeout);

        auto id = opts.hostId.value_or(
            std::string("fishnets-ws-client/") + BOOST_BEAST_VERSION_STRING
        );
        m_ws.set_option(bsb::decorator([id = std::move(id)](ws::request_type& req) {
            req.set(http::field::user_agent, id);
        }));
    }

    void onReadyForWSHandshake(beast::error_code e) {
        if (e) return failed(e, "ws connect");

        setInitialOptions(m_handler->getInitialOptions());

        m_ws.async_handshake(m_host, m_target,
            beast::bind_front_handler(&ClientConnectorT::onConnectionEstablished, shared_from(this)));
    }

    void onConnectionEstablished(beast::error_code e) {
        if (e) return failed(e, "establish");
        m_handler->onConnected(
            std::make_unique<WebSocketImplT<RawSocket>>(std::move(m_ws)),
            m_target
        );
    }
};

struct ClientConnectorWs final : public ClientConnectorT<RawWs> {
    using ClientConnectorT<RawWs>::ClientConnectorT;
    void handshake() override {
        onReadyForWSHandshake({});
    }
};

#if FISHNETS_ENABLE_SSL
struct ClientConnectorSsl final : public ClientConnectorT<RawWsSsl> {
    using ClientConnectorT<RawWsSsl>::ClientConnectorT;
    void handshake() override {
        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(m_ws.next_layer().native_handle(), m_host.c_str())) {
            auto e = beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
            return failed(e, "ssl handshake");
        }

        m_ws.next_layer().async_handshake(ssl::stream_base::client,
            beast::bind_front_handler(&ClientConnectorSsl::onReadyForWSHandshake, shared_from(this)));
    }
};
#endif

} // namespace

namespace impl {
class WsServer : public itlib::enable_shared_from {
public:
    net::io_context& m_ctx;
    WsServerHandlerPtr m_handler;

    std::vector<tcp::acceptor> m_acceptors;

    SslContext* m_sslCtx = nullptr;

    WsServer(
        net::io_context& ctx,
        const WsServerHandlerPtr& handler,
        std::span<const tcp::endpoint> endpoints,
        SslContext* sslCtx
    )
        : m_ctx(ctx)
        , m_handler(handler)
        , m_sslCtx(sslCtx)
    {
        for (auto& ep : endpoints) {
            m_acceptors.emplace_back(ctx, ep);
        }
    }

    void start() {
        for (auto& a : m_acceptors) {
            doAccept(a);
        }
    }

    void stop() {
        for (auto& a : m_acceptors) {
            net::post(a.get_executor(), [&a, pl = shared_from_this()]() {
                a.close();
            });
        }
    }

    void doAccept(tcp::acceptor& a) {
        a.async_accept(make_strand(m_ctx), [&a, this, pl = shared_from_this()](beast::error_code e, tcp::socket socket) {
            onAccept(a, e, std::move(socket));
        });
    }

    void onAccept(tcp::acceptor& a, beast::error_code e, tcp::socket socket) {
        auto localEndpoint = EndpointInfo_fromTcp(a.local_endpoint());

        if (e) {
            m_handler->m_server = {};
            m_handler->onError(e.message());
            return;
        }

        // init session handler
        auto ep = getEndpointInfoOf(socket);
        if (!ep) {
            m_handler->onError("socket disconnected while accepting");
            doAccept(a);
            return;
        }

        auto conHandler = m_handler->onAccept(localEndpoint, *ep);

        if (!conHandler) {
            m_handler->onError("session declined");
            doAccept(a);
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

        con->setInitialOptions(conHandler->getInitialOptions());
        con->m_handler = std::move(conHandler);
        con->accept();

        // accept more sessions
        doAccept(a);
    }
};

} // namespace impl

WsServerHandler::~WsServerHandler() = default;

void WsServerHandler::onError(std::string msg) {
    fprintf(stderr, "WebSocket connection error: %s\n", msg.c_str());
}

void WsServerHandler::stop() {
    auto server = m_server.lock();
    if (!server) return;
    server->stop();
    server = {};
}

void Context::Impl::wsServe(std::span<const tcp::endpoint> eps, WsServerHandlerPtr handler, SslContext* ssl) {
    if (!handler->m_server.expired()) {
        handler->onError("handler already serving");
        return;
    }
    auto server = std::make_shared<impl::WsServer>(ctx, handler, eps, ssl);
    handler->m_server = server;

    server->start();
}

void Context::wsServe(std::span<const EndpointInfo> endpoints, WsServerHandlerPtr handler, SslContext* ssl) {
    auto eps = EndpointInfo_toTcp(endpoints);
    m_impl->wsServe(eps, std::move(handler), ssl);
}

void Context::wsServeLocalhost(uint16_t port, WsServerHandlerPtr handler, SslContext* ssl) {
    const tcp::endpoint eps[] = {
        {net::ip::address_v4::loopback(), port},
        {net::ip::address_v6::loopback(), port},
    };
    m_impl->wsServe(eps, std::move(handler), ssl);
}

static void Context_wsConnect(
    Context& self,
    WsConnectionHandlerPtr& handler,
    std::vector<tcp::endpoint> eps,
    std::string host,
    std::string target,
    SslContext* ssl
) {
    std::shared_ptr<ClientConnector> con;

    auto strand = make_strand(self.impl().ctx);
#if FISHNETS_ENABLE_SSL
    if (ssl) {
        con = std::make_shared<ClientConnectorSsl>(RawWsSsl(std::move(strand), ssl->impl().ctx));
    }
    else
#endif
    {
        con = std::make_shared<ClientConnectorWs>(RawWs(std::move(strand)));
    }

    con->m_handler = std::move(handler);

    con->m_host = std::move(host);
    con->m_target = std::move(target);

    con->connect(std::move(eps));
}

void Context::wsConnect(
    WsConnectionHandlerPtr handler,
    std::span<const EndpointInfo> endpoints,
    std::string_view target,
    SslContext* ssl
) {
    if (endpoints.empty()) {
        handler->onConnectionError("no endpoints provided");
        return;
    }

    if (target.empty()) target = "/";

    auto eps = EndpointInfo_toTcp(endpoints);

    Context_wsConnect(
        *this,
        handler,
        std::move(eps),
        {},
        std::string(target),
        ssl
    );
}

void Context::wsConnect(WsConnectionHandlerPtr handler, std::string_view url, SslContext* sslCtx) {
    auto uriSplit = furi::uri_split::from_uri(url);
    if (uriSplit.scheme) {
        if (uriSplit.scheme == "http" || uriSplit.scheme == "ws") {
            sslCtx = nullptr;
        }
        else if (uriSplit.scheme == "https" || uriSplit.scheme == "wss") {
            if (!sslCtx) {
                handler->onConnectionError("https scheme requires an ssl context");
                return;
            }
        }
        else {
            handler->onConnectionError(std::string("unsupported scheme: ") + std::string(uriSplit.scheme));
            return;
        }
    }

    auto authSplit = furi::authority_split::from_authority(uriSplit.authority);
    if (authSplit.userinfo) {
        handler->onConnectionError("userinfo not supported");
        return;
    }

    auto port = authSplit.port;
    if (!port) {
        port = sslCtx ? "443" : "80";
    }

    auto& resolver = m_impl->get_resolver();
    resolver.async_resolve(authSplit.host, port,
        [
            this,
            handler,
            sslCtx,
            host = std::string(authSplit.host),
            target = std::string(uriSplit.req_path)
        ](beast::error_code e, tcp::resolver::results_type results) mutable {
            if (e) {
                handler->onConnectionError(std::string("resolve: ") + e.message());
                return;
            }

            std::vector<tcp::endpoint> eps;
            for (auto& ep : results) {
                eps.push_back(ep.endpoint());
            }

            Context_wsConnect(*this, handler, std::move(eps), std::move(host), std::move(target), sslCtx);
        }
    );
}

HttpResponseSocket::HttpResponseSocket() = default;
HttpResponseSocket::~HttpResponseSocket() = default;

struct HttpResponseSocketImpl : public HttpResponseSocket {
    using HttpResponseSocket::m_executor;
};

namespace {

using request_t = http::request<http::buffer_body>;
auto ua = net::use_awaitable;

template <typename Stream>
struct HttpResponseSocketT final : public HttpResponseSocketImpl {
    Stream m_stream;

    explicit HttpResponseSocketT(Stream&& stream) : m_stream(std::move(stream)) {
        m_executor = itlib::make_shared(Executor{m_stream.get_executor()});
    }

    void close(CloseCb) override {}
};

struct HttpConnector {
    virtual ~HttpConnector() = default;
    virtual net::awaitable<void> handshake(std::string_view host) = 0;
    virtual net::awaitable<size_t> write(const request_t& req) = 0;
    virtual net::awaitable<size_t> readHeader(beast::flat_buffer& buf, http::response_parser<http::empty_body>& parser) = 0;

    virtual std::unique_ptr<HttpResponseSocket> makeResponseSocket() = 0;
};

template <typename Stream>
struct HttpConnectorT : public HttpConnector {
    Stream m_stream;

    template <typename... Args>
    explicit HttpConnectorT(Args&&... args) : m_stream(std::forward<Args>(args)...) {}

    virtual net::awaitable<size_t> write(const request_t& req) final override {
        return http::async_write(m_stream, req, ua);
    }
    virtual net::awaitable<size_t> readHeader(beast::flat_buffer& buf, http::response_parser<http::empty_body>& parser) final override {
        return http::async_read_header(m_stream, buf, parser, ua);
    }

    virtual std::unique_ptr<HttpResponseSocket> makeResponseSocket() final override {
        return std::make_unique<HttpResponseSocketT<Stream>>(std::move(m_stream));
    }
};

struct HttpConnectorTcp final : public HttpConnectorT<beast::tcp_stream> {
    using HttpConnectorT<beast::tcp_stream>::HttpConnectorT;
    virtual net::awaitable<void> handshake(std::string_view) override { co_return; } // no-op for non-ssl
};

http::verb HttpRequestHeader_toBeastVerb(HttpRequestHeader::Method method) {
    switch (method) {
    case HttpRequestHeader::GET:  return http::verb::get;
    case HttpRequestHeader::HEAD: return http::verb::head;
    case HttpRequestHeader::POST: return http::verb::post;
    case HttpRequestHeader::PUT:  return http::verb::put;
    case HttpRequestHeader::DEL:  return http::verb::delete_;
    default: return http::verb::unknown;
    }
}

static net::awaitable<void> Context_httpRequest(
    Context& self,
    request_t req,
    HttpResponseHandlerPtr handler,
    SslContext* sslCtx
) {
    const std::string_view scheme = sslCtx ? "https" : "http";

    beast::flat_buffer buffer;

    auto opts = handler->getOptions();

    auto& asioCtx = self.impl().ctx;

    for (int i = 0; i <= opts.maxRedirects; ++i) try {
        auto host = req[http::field::host];

        auto stream = co_await [&]() -> net::awaitable<std::unique_ptr<HttpConnector>> {
            tcp::resolver& resolver = self.impl().get_resolver();
            auto resolved = co_await resolver.async_resolve(host, scheme, ua);

            beast::tcp_stream init_stream(asioCtx);
            co_await init_stream.async_connect(resolved, ua);

#if FISHNETS_ENABLE_SSL
            if (sslCtx) {

            }
#endif
            co_return std::make_unique<HttpConnectorTcp>(std::move(init_stream));
        }();

        co_await stream->handshake(host);
        co_await stream->write(req);

        http::response_parser<http::empty_body> parser;
        parser.body_limit(std::numeric_limits<std::uint64_t>::max());

        co_await stream->readHeader(buffer, parser);

        auto& header = parser.get().base();

        // instead of juggling redirects, just look for location header
        auto f = header.find(http::field::location);
        if (f != header.end()) {
            // redirect
            // update url and loop again
            auto loc = f->value();
            if (loc.starts_with('/')) {
                // relative path
                req.target(loc);
            }
            else {
                // absolute path
                auto split = furi::uri_split::from_uri(loc);
                if (split.scheme && split.scheme != scheme) {
                    handler->onError("redirect to different scheme not supported");
                    co_return;
                }
                req.set(http::field::host, split.authority);
                req.target(split.req_path);
            }

            // loop for another redirect
            continue;
        }

        // no redirect, must be ok
        if (parser.get().result() != http::status::ok) {
            std::string error = "http response: ";
            error += std::to_string(parser.get().result_int());
            handler->onError(std::move(error));
            co_return;
        }

        auto respSocket = stream->makeResponseSocket();
        handler->onReady(std::move(respSocket), host, req.target());
        co_return;
    }
    catch (const std::exception& e) {
        handler->onError(e.what());
        co_return;
    }

    handler->onError("too many redirects");
}

} // namespace

void Context::httpRequest(
    const HttpRequestHeader& header,
    HttpRequestBody body,
    HttpResponseHandlerPtr handler,
    SslContext* sslCtx
) {
    request_t req;
    req.method(HttpRequestHeader_toBeastVerb(header.method));
    req.target(header.target);
    req.set(http::field::host, header.host);

    if (header.fields.userAgent.empty()) {
        req.set(http::field::user_agent, std::string("fishnets-http/") + BOOST_BEAST_VERSION_STRING);
    }
    else {
        req.set(http::field::user_agent, header.fields.userAgent);
    }

    if (!header.fields.contentType.empty()) {
        req.set(http::field::content_type, header.fields.contentType);
    }

    if (header.fields.accept.empty()) {
        req.set(http::field::accept, "*/*");
    }
    else {
        req.set(http::field::accept, header.fields.accept);
    }

    if (header.fields.keepAlive) {
        req.keep_alive(true);
    }

    if (header.scheme == HttpRequestHeader::HTTP) {
        sslCtx = nullptr;
    }

    net::co_spawn(
        m_impl->ctx,
        Context_httpRequest(*this, std::move(req), std::move(handler), sslCtx),
        net::detached
    );
}

ExecutorPtr Context::makeExecutor() {
    return itlib::make_shared(Executor{make_strand(m_impl->ctx)});
}

void post(Executor& e, Task task) {
    post(e.ex, std::move(task));
}

Timer::Timer() = default;
Timer::~Timer() = default; // export vtable

struct TimerImpl final : public Timer {
public:
    net::steady_timer m_timer;

    explicit TimerImpl(Executor& ex) : m_timer(ex.ex) {}

    virtual void expireAfter(std::chrono::milliseconds timeFromNow) override {
        m_timer.expires_after(timeFromNow);
    }

    virtual void cancel() override {
        m_timer.cancel();
    }
    virtual void cancelOne() override {
        m_timer.cancel_one();
    }

    virtual void addCallback(Cb cb) override {
        m_timer.async_wait(std::move(cb));
    }
};

TimerPtr Timer::create(const ExecutorPtr& ex) {
    return std::make_unique<TimerImpl>(*ex);
}

} // namespace fishnets
