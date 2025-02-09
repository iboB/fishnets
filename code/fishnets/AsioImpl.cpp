// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "WsSessionHandler.hpp"
#include "WsSessionOptions.hpp"
#include "Context.hpp"
#include "ContextWorkGuard.hpp"
#include "WebSocket.hpp"

#define BOOST_BEAST_USE_STD_STRING_VIEW 1

#if defined(_MSC_VER)
#   pragma warning (disable: 4100)
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>

#include <itlib/make_ptr.hpp>

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

} // namespace

namespace impl {

class WsSession {
public:
    beast::flat_buffer m_readBuf;
    itlib::span<uint8_t> m_userBuf;

    // only relevant when accepting
    // cleared after the connection is established
    http::request<http::string_body> m_upgradeRequest;

    // target of web socket connection (typically "/")
    std::string m_target;

    virtual ~WsSession() = default;
};

template <typename WebSocket>
struct WsSessionT : public WsSession {
    WebSocket m_socket;
};

using WsSessionWs = WsSessionT<ws::stream<tcp::socket>>;

template <typename WebSocket>
void WsSession_onUpgradeRequest(WsSessionT<WebSocket>& self, const WsSessionHandlerPtr& handler, beast::error_code e) {
    // if (e) return failed(e, "upgrade");
    if (!ws::is_upgrade(self.m_upgradeRequest)) {
        //return failed(websocket::error::no_connection_upgrade, "upgrade");
    }
    self.m_target = self.m_upgradeRequest.target();
    //acceptUpgrade();
    self.m_readBuf.clear();
}

void WsSession_accept(WsSessionWs& self, const WsSessionHandlerPtr& handler) {
    // read upgrade request to accept
    http::async_read(self.m_socket.next_layer(), self.m_readBuf, self.m_upgradeRequest,
        [&self, handler](beast::error_code ec, size_t /*bytesTransfered*/) {
            WsSession_onUpgradeRequest(self, handler, {});
        }
    );
}

} // namespace impl

namespace {
struct WsServer : public itlib::enable_shared_from {
    net::io_context& m_ctx;

    tcp::acceptor m_acceptor;

    WsServerSessionHandlerFactory m_factory;

#if FISHNETS_ENABLE_SSL
    std::unique_ptr<ssl::context> m_sslCtx;
    ServerSslSettings m_sslSettings; // here we persist the strings provided by the user
#endif

    WsServer(
        net::io_context& ctx,
        WsServerSessionHandlerFactory&& factory,
        tcp::endpoint endpoint,
        ServerSslSettings* sslSettings
    )
        : m_ctx(ctx)
        , m_acceptor(ctx, endpoint)
        , m_factory(std::move(factory))
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
        auto session = m_factory(*ep);
        if (!session) {
            std::cout << "session declined\n";
            doAccept();
            return;
        }

        // accept more sessions
        doAccept();
    }
};
} // namespace

void Context::wsServe(EndpointInfo endpoint, WsServerSessionHandlerFactory factory, const ServerSslSettings* ssl) {
}

void Context::wsConnect(EndpointInfo endpoint, WsClientSessionHandlerFactory factory, const ClientSslSettings* ssl) {
}

} // namespace fishnets
