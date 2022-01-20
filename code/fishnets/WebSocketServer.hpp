// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#pragma once
#include "API.h"

#include "WebSocketSessionFactory.hpp"

#include <cstdint>

namespace fishnets
{
struct WebSocketServerSSLSettings;
class Server;

class FISHNETS_API WebSocketServer
{
public:
    // constructing a server will immediately complete
    // it will launch a number of io threads
    // destroying the server will stop the network io
    // the user must keep it alive for as long as needed
    WebSocketServer(
        WebSocketSessionFactoryFunc sessionFactory,
        uint16_t port,
        int numThreads = 1,
        WebSocketServerSSLSettings* sslSettings = nullptr);
    ~WebSocketServer();

    WebSocketServer(const WebSocketServer&) = delete;
    WebSocketServer& operator=(const WebSocketServer&) = delete;
    WebSocketServer(WebSocketServer&&) noexcept = delete;
    WebSocketServer& operator=(WebSocketServer&&) noexcept = delete;

private:
    std::unique_ptr<Server> m_server;
};
}
