// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
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

namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace http = beast::http;
using tcp = net::ip::tcp;

class session : public std::enable_shared_from_this<session>
{
    websocket::stream<tcp::socket> m_ws;
    net::executor m_executor;

    beast::flat_buffer m_read_buf;
    http::request<http::string_body> m_upgrade_req;
    std::string m_target;
public:
    session(tcp::socket&& s)
        : m_ws(std::move(s))
        , m_executor(m_ws.get_executor())
    {}

    void failed(beast::error_code e, const char* source)
    {
        std::cerr << source << " error: " << e.message() << '\n';
    }

    void closed()
    {
        std::cout << "session closed\n";
    }

    void on_close(beast::error_code e)
    {
        if (e) return failed(e, "close");
    }

    void do_close()
    {
        m_ws.async_close(websocket::close_code::normal, beast::bind_front_handler(&session::on_close, shared_from_this()));
    }

    void on_read(beast::error_code e, size_t)
    {
        if (e == websocket::error::closed) return closed();
        if (e) return failed(e, "read");

        if (m_ws.got_text())
        {
            std::string_view str(static_cast<char*>(m_read_buf.data().data()), m_read_buf.size());
            std::cout << "received: " << str << std::endl; // flush intentionally
        }

        m_read_buf.clear();
        do_read();
    }

    void do_read()
    {
        m_ws.async_read(m_read_buf, beast::bind_front_handler(&session::on_read, shared_from_this()));
    }

    void on_connected(beast::error_code e)
    {
        if (e) return failed(e, "establish");

        m_upgrade_req = {}; // clear request to save memory

        do_read();
    }

    void on_upgrade_request(beast::error_code e, size_t /*bytesTransfered*/)
    {
        if (e) return failed(e, "upgrade");
        if (!websocket::is_upgrade(m_upgrade_req)) return failed(websocket::error::no_connection_upgrade, "upgrade");
        m_target = m_upgrade_req.target();
        m_ws.async_accept(m_upgrade_req,
            beast::bind_front_handler(&session::on_connected, shared_from_this()));
        m_read_buf.clear();
    }

    void set_server_options()
    {
        auto timeout = websocket::stream_base::timeout::suggested(beast::role_type::server);
        m_ws.set_option(timeout);
    }

    void accept()
    {
        http::async_read(m_ws.next_layer(), m_read_buf, m_upgrade_req,
            beast::bind_front_handler(&session::on_upgrade_request, shared_from_this()));
    }
};

class server
{
    net::io_context m_ctx;
    tcp::acceptor m_acceptor;
    std::vector<std::thread> m_threads;
public:
    server(int nthreads)
        : m_ctx(nthreads)
        , m_acceptor(m_ctx, tcp::endpoint(tcp::v4(), 7654))
    {
        do_accept();
        for (int i = 0; i < nthreads; ++i)
        {
            m_threads.emplace_back([this]() { m_ctx.run(); });
        }

    }

    ~server()
    {
        m_ctx.stop();
        for (auto& t : m_threads) {
            t.join();
        }
    }

    void do_accept()
    {
        m_acceptor.async_accept(net::make_strand(m_ctx), beast::bind_front_handler(&server::on_accept, this));
    }

    void on_accept(beast::error_code e, tcp::socket socket)
    {
        if (e)
        {
            std::cerr << "onAccept error: " << e << '\n';
            return;
        }

        auto s = std::make_shared<session>(std::move(socket));
        s->set_server_options(); // OFFENDER
        s->accept();

        // accept more sessions
        do_accept();
    }
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
    server s(2);
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