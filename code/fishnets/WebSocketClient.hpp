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
#include <string>

namespace fishnets
{
struct WebSocketClientSSLSettings;
class Client;

class FISHNETS_API WebSocketClient
{
public:
    WebSocketClient(WebSocketSessionFactoryFunc sessionFactory, WebSocketClientSSLSettings* sslSettings = nullptr);
    ~WebSocketClient();

    // Blocks the current thread until the client session is closed
    // Multiple connections (even concurrent ones) are valid
    void connect(const std::string& addr, uint16_t port);

    // Stops the client: disconnects currently connected sessions
    // valid on any thread
    // Caling this is not necessary if connection has already exited and is simply never called again
    void stop();

    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(const WebSocketClient&) = delete;
    WebSocketClient(WebSocketClient&&) noexcept = delete;
    WebSocketClient& operator=(WebSocketClient&&) noexcept = delete;

private:
    std::unique_ptr<Client> m_client;
};

}
