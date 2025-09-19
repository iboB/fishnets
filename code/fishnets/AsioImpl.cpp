// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsServe.hpp"
#include "WsConnect.hpp"
#include "MakeHttpRequest.hpp"
#include "MakeSimpleHttpRequest.hpp"

#include "WebSocket.hpp"
#include "WsConnectionHandler.hpp"
#include "WsServerHandler.hpp"
#include "WebSocketOptions.hpp"

#include "HttpRequestDesc.hpp"
#include "HttpMsgBody.hpp"
#include "HttpResponseHandler.hpp"
#include "HttpRequestOptions.hpp"
#include "HttpResponseSocket.hpp"

#include <xeq/context.hpp>
#include <xeq/executor.hpp>

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

#include <cassert>
#include <unordered_map>
#include <cstdio>
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

struct XeqContextObject {
    tcp::resolver resolver;
};

tcp::resolver& getResolver(xeq::context& ctx) {
    static constexpr std::string_view key = "fishnets";
    auto obj = ctx.get_object(key);
    if (obj) {
        auto holder = static_cast<XeqContextObject*>(obj.get());
        return holder->resolver;
    }
    auto holder = itlib::make_shared(XeqContextObject{tcp::resolver(ctx.as_asio_io_context())});
    ctx.attach_object(key, holder);
    return holder->resolver;
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

    explicit WebSocketImplT(xeq::executor_ptr ex, RawSocket&& ws) : m_ws(std::move(ws)) {
        m_executor = std::move(ex);
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
                WebSocket::ByteSpan span(static_cast<std::byte*>(m_growableBuf.data().data()), m_growableBuf.size());
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
    xeq::executor_ptr m_executor;
    RawSocket m_ws;

    explicit ServerConnectorT(xeq::executor_ptr ex, RawSocket&& ws)
        : m_executor(std::move(ex))
        , m_ws(std::move(ws))
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
            std::make_unique<WebSocketImplT<RawSocket>>(std::move(m_executor), std::move(m_ws)),
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
    xeq::executor_ptr m_executor;
    RawSocket m_ws;

    explicit ClientConnectorT(xeq::executor_ptr ex, RawSocket&& ws)
        : m_executor(std::move(ex))
        , m_ws(std::move(ws)) {}

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
            std::make_unique<WebSocketImplT<RawSocket>>(std::move(m_executor), std::move(m_ws)),
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
    xeq::context& m_ctx;
    WsServerHandlerPtr m_handler;

    std::vector<tcp::acceptor> m_acceptors;

    SslContext* m_sslCtx = nullptr;

    WsServer(
        xeq::context& ctx,
        const WsServerHandlerPtr& handler,
        std::span<const tcp::endpoint> endpoints,
        SslContext* sslCtx
    )
        : m_ctx(ctx)
        , m_handler(handler)
        , m_sslCtx(sslCtx)
    {
        for (auto& ep : endpoints) {
            m_acceptors.emplace_back(ctx.as_asio_io_context(), ep);
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
        auto strand = m_ctx.make_strand();
        auto asioStrand = strand->as_asio_executor();
        a.async_accept(
            std::move(asioStrand),
            [&a, strand = std::move(strand), this, pl = shared_from_this()](beast::error_code e, tcp::socket socket) mutable {
                onAccept(a, e, std::move(strand), std::move(socket));
            }
        );
    }

    void onAccept(tcp::acceptor& a, beast::error_code e, xeq::executor_ptr socketEx, tcp::socket socket) {
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
            con = std::make_shared<ServerConnectorSsl>(std::move(socketEx), RawWsSsl(std::move(socket), m_sslCtx->impl().ctx));
        }
        else
#endif
        {
            con = std::make_shared<ServerConnectorWs>(std::move(socketEx), RawWs(std::move(socket)));
        }

        con->setInitialOptions(conHandler->getInitialOptions());
        con->m_handler = std::move(conHandler);
        con->accept();

        // accept more sessions
        doAccept(a);
    }

    static void serve(xeq::context& ctx, std::span<const tcp::endpoint> eps, WsServerHandlerPtr handler, SslContext* ssl) {
        if (!handler->m_server.expired()) {
            handler->onError("handler already serving");
            return;
        }
        auto server = std::make_shared<WsServer>(ctx, handler, eps, ssl);
        handler->m_server = server;

        server->start();
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

void wsServe(xeq::context& ctx, std::span<const EndpointInfo> endpoints, WsServerHandlerPtr handler, SslContext* ssl) {
    auto eps = EndpointInfo_toTcp(endpoints);
    impl::WsServer::serve(ctx, eps, std::move(handler), ssl);
}

void wsServeLocalhost(xeq::context& ctx, uint16_t port, WsServerHandlerPtr handler, SslContext* ssl) {
    const tcp::endpoint eps[] = {
        {net::ip::address_v4::loopback(), port},
        {net::ip::address_v6::loopback(), port},
    };
    impl::WsServer::serve(ctx, eps, std::move(handler), ssl);
}

static void Context_wsConnect(
    xeq::context& ctx,
    WsConnectionHandlerPtr& handler,
    std::vector<tcp::endpoint> eps,
    std::string host,
    std::string target,
    SslContext* ssl
) {
    std::shared_ptr<ClientConnector> con;

    auto strand = ctx.make_strand();
    auto asioStrand = strand->as_asio_executor();
#if FISHNETS_ENABLE_SSL
    if (ssl) {
        con = std::make_shared<ClientConnectorSsl>(std::move(strand), RawWsSsl(std::move(asioStrand), ssl->impl().ctx));
    }
    else
#endif
    {
        con = std::make_shared<ClientConnectorWs>(std::move(strand), RawWs(std::move(asioStrand)));
    }

    con->m_handler = std::move(handler);

    con->m_host = std::move(host);
    con->m_target = std::move(target);

    con->connect(std::move(eps));
}

void wsConnect(
    xeq::context& ctx,
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
        ctx,
        handler,
        std::move(eps),
        {},
        std::string(target),
        ssl
    );
}

void wsConnect(xeq::context& ctx, WsConnectionHandlerPtr handler, std::string_view url, SslContext* sslCtx) {
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

    auto& resolver = getResolver(ctx);
    resolver.async_resolve(authSplit.host, port,
        [
            &ctx,
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

            Context_wsConnect(ctx, handler, std::move(eps), std::move(host), std::move(target), sslCtx);
        }
    );
}

HttpResponseSocket::HttpResponseSocket() = default;
HttpResponseSocket::~HttpResponseSocket() = default;

struct HttpResponseSocketImpl : public HttpResponseSocket {
    using HttpResponseSocket::m_executor;
    http::response_parser<http::buffer_body> m_parser;

    beast::flat_buffer m_flatBuf;
    ByteSpan m_dataBuf;

    HttpResponseSocketImpl(http::response_parser<http::empty_body>& eparser)
        : m_parser(std::move(eparser))
    {}
};

namespace {

using request_t = http::request<http::span_body<const std::byte>>;
auto ua = net::use_awaitable;

template <typename Stream>
struct HttpResponseSocketT final : public HttpResponseSocketImpl {
    Stream m_stream;

    explicit HttpResponseSocketT(http::response_parser<http::empty_body>& eparser, xeq::executor_ptr ex, Stream&& stream)
        : HttpResponseSocketImpl(eparser)
        , m_stream(std::move(stream))
    {
        m_executor = std::move(ex);
    }

    bool connected() const override {
        return beast::get_lowest_layer(m_stream).socket().is_open();
    }

    void recv(ByteSpan span, RecvCb cb) override {
        auto onRead = [this, cb = std::move(cb)](beast::error_code e, size_t size) {
            if (e && e != http::error::need_buffer && e != http::error::end_of_chunk) {
                cb(itlib::unexpected(e.message()));
                return;
            }

            cb(Packet{
                .data = m_dataBuf.subspan(0, size),
                .complete = m_parser.is_done()
            });

            m_dataBuf = {};
        };

        m_dataBuf = span;
        auto body = m_parser.get().body();
        body.data = m_dataBuf.data();
        body.size = m_dataBuf.size();
        http::async_read(m_stream, m_flatBuf, m_parser, std::move(onRead));
    }

    void close() override {
        beast::get_lowest_layer(m_stream).close();
    }
};

struct HttpConnector {
    virtual ~HttpConnector() = default;
    virtual net::awaitable<void> handshake(std::string_view host) = 0;
    virtual net::awaitable<size_t> write(const request_t& req) = 0;
    virtual net::awaitable<size_t> readHeader(beast::flat_buffer& buf, http::response_parser<http::empty_body>& parser) = 0;

    virtual net::awaitable<size_t> readFullBody(beast::flat_buffer& buf, http::response_parser<http::string_body>& parser) = 0;

    virtual std::unique_ptr<HttpResponseSocket> makeResponseSocket(http::response_parser<http::empty_body>& parser) = 0;
};

template <typename Stream>
struct HttpConnectorT : public HttpConnector {
    xeq::executor_ptr m_executor;
    Stream m_stream;

    template <typename... Args>
    explicit HttpConnectorT(xeq::executor_ptr ex, Args&&... args)
        : m_executor(std::move(ex))
        , m_stream(std::forward<Args>(args)...)

    {}

    virtual net::awaitable<size_t> write(const request_t& req) final override {
        return http::async_write(m_stream, req, ua);
    }
    virtual net::awaitable<size_t> readHeader(beast::flat_buffer& buf, http::response_parser<http::empty_body>& parser) final override {
        return http::async_read_header(m_stream, buf, parser, ua);
    }

    virtual net::awaitable<size_t> readFullBody(beast::flat_buffer& buf, http::response_parser<http::string_body>& parser) {
        return http::async_read(m_stream, buf, parser, ua);
    }

    virtual std::unique_ptr<HttpResponseSocket> makeResponseSocket(http::response_parser<http::empty_body>& parser) final override {
        return std::make_unique<HttpResponseSocketT<Stream>>(parser, std::move(m_executor), std::move(m_stream));
    }
};

struct HttpConnectorTcp final : public HttpConnectorT<beast::tcp_stream> {
    using HttpConnectorT<beast::tcp_stream>::HttpConnectorT;
    virtual net::awaitable<void> handshake(std::string_view) override { co_return; } // no-op for non-ssl
};

#if FISHNETS_ENABLE_SSL
struct HttpConnectorSsl final : public HttpConnectorT<beast::ssl_stream<beast::tcp_stream>> {
    using HttpConnectorT<beast::ssl_stream<beast::tcp_stream>>::HttpConnectorT;
    virtual net::awaitable<void> handshake(std::string_view host) override {
        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(m_stream.native_handle(), host.data())) {
            auto e = beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
            throw beast::system_error(e);
        }
        return m_stream.async_handshake(ssl::stream_base::client, ua);
    }
};
#endif

template <bool Simple>
static net::awaitable<void> Context_httpRequest(
    xeq::context& ctx,
    request_t req,
    ConstHttpMsgBody body,
    HttpRequestOptions opts,
    HttpResponseHandlerPtr handler,
    SimpleHttpRequestCb cb,
    SslContext* sslCtx
) {
    assert((Simple && cb) || handler);

    const std::string_view scheme = sslCtx ? "https" : "http";

    beast::flat_buffer buffer;

    req.body() = body.span();

    std::string error;
    for (int i = 0; i <= opts.maxRedirects; ++i) try {
        buffer.clear();

        auto host = req[http::field::host];

        auto stream = co_await [&]() -> net::awaitable<std::unique_ptr<HttpConnector>> {
            tcp::resolver& resolver = getResolver(ctx);
            auto resolved = co_await resolver.async_resolve(host, scheme, ua);

            beast::tcp_stream init_stream(ctx.as_asio_io_context());
            co_await init_stream.async_connect(resolved, ua);

            if (opts.timeout) {
                init_stream.expires_after(*opts.timeout);
            }

            if (opts.disableNagle) {
                init_stream.socket().set_option(tcp::no_delay(true));
            }

#if FISHNETS_ENABLE_SSL
            if (sslCtx) {
                co_return std::make_unique<HttpConnectorSsl>(ctx.get_executor(), std::move(init_stream), sslCtx->impl().ctx);
            }
#endif

            co_return std::make_unique<HttpConnectorTcp>(ctx.get_executor(), std::move(init_stream));
        }();

        co_await stream->handshake(host);
        co_await stream->write(req);

        http::response_parser<http::empty_body> eparser;

        co_await stream->readHeader(buffer, eparser);

        auto& header = eparser.get().base();

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
                auto split = furi::uri_split::from_uri((std::string_view)loc);
                if (split.scheme && split.scheme != scheme) {
                    error = "redirect to different scheme not supported";
                    break;
                }
                req.set(http::field::host, split.authority);
                req.target(split.req_path);
            }

            // loop for another redirect
            continue;
        }

        // no redirect, must be ok
        if (eparser.get().result() != http::status::ok) {
            error = "http response: ";
            error += std::to_string(eparser.get().result_int());
            break;
        }

        // parser.body_limit(opts.maxResponseSize.value_or(std::numeric_limits<std::size_t>::max()));
        if constexpr (Simple) {
            if (eparser.is_done()) {
                cb({});
                co_return;
            }

            http::response_parser<http::string_body> parser(std::move(eparser));
            co_await stream->readFullBody(buffer, parser);
            cb(parser.release().body());
        }
        else {
            auto respSocket = stream->makeResponseSocket(eparser);
            handler->onReady(std::move(respSocket), host, req.target());
        }

        co_return;
    }
    catch (const std::exception& e) {
        error = e.what();
    }

    if constexpr (Simple) {
        cb(itlib::unexpected(std::move(error)));
    }
    else {
        handler->onError(std::move(error));
    }
}

request_t requestFromDesc(const HttpRequestDesc& desc) {
    request_t req;
    req.method(http::string_to_verb(desc.method));
    req.target(desc.target);
    req.set(http::field::host, desc.host);

    if (desc.fields.userAgent.empty()) {
        req.set(http::field::user_agent, std::string("fishnets-http/") + BOOST_BEAST_VERSION_STRING);
    }
    else {
        req.set(http::field::user_agent, desc.fields.userAgent);
    }

    if (!desc.fields.contentType.empty()) {
        req.set(http::field::content_type, desc.fields.contentType);
    }

    if (desc.fields.accept.empty()) {
        req.set(http::field::accept, "*/*");
    }
    else {
        req.set(http::field::accept, desc.fields.accept);
    }

    if (desc.fields.keepAlive) {
        req.keep_alive(true);
    }

    return req;
}

} // namespace

void makeHttpRequest(
    xeq::context& ctx,
    const HttpRequestDesc& desc,
    ConstHttpMsgBody body,
    HttpResponseHandlerPtr handler,
    SslContext* sslCtx
) {
    auto req = requestFromDesc(desc);

    if (desc.scheme == HttpRequestDesc::HTTP) {
        sslCtx = nullptr;
    }

    net::co_spawn(
        ctx.as_asio_io_context(),
        Context_httpRequest<false>(
            ctx, std::move(req), std::move(body), handler->getOptions(), handler, {}, sslCtx),
        net::detached
    );
}

void makeSimpleHttpRequest(
    xeq::context& ctx,
    const HttpRequestDesc& desc,
    ConstHttpMsgBody body,
    SimpleHttpRequestCb cb,
    HttpRequestOptions opts,
    SslContext* sslCtx
) {
    auto req = requestFromDesc(desc);

    if (desc.scheme == HttpRequestDesc::HTTP) {
        sslCtx = nullptr;
    }

    net::co_spawn(
        ctx.as_asio_io_context(),
        Context_httpRequest<true>(
            ctx, std::move(req), std::move(body), std::move(opts), {}, std::move(cb), sslCtx),
        net::detached
    );
}

} // namespace fishnets
