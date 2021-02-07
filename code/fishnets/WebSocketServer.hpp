// fishnets
// Copyright (c) 2021 Borislav Stanimirov
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
struct SSLSettings;
class Server;

class FISHNETS_API WebSocketServer
{
public:
    WebSocketServer(WebSocketSessionFactoryFunc sessionFactory, uint16_t port, int numThreads = 1, SSLSettings* sslSettings = nullptr);
    ~WebSocketServer();

    WebSocketServer(const WebSocketServer&) = delete;
    WebSocketServer& operator=(const WebSocketServer&) = delete;
    WebSocketServer(WebSocketServer&&) noexcept = delete;
    WebSocketServer& operator=(WebSocketServer&&) noexcept = delete;

private:
    std::unique_ptr<Server> m_server;
};
}
