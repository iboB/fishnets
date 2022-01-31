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
#include <string_view>

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
    // Multiple non-concurrent connections are valid as long as you restart after each one
    // Only connect if there is no other active connection with this client
    // After this function exits the client is in a stopped state
    void connect(const std::string& addr, uint16_t port, std::string_view target = "/");

    // Stops the client: disconnects currently connected sessions and prevents future ones from connecting
    // Valid on any thread
    // Caling this is not necessary if connection has already exited and is simply never called again
    void stop();

    // After a connect completes the client is in a stopped state
    // (regardless of whether stop has been called or the session was closed naturally)
    // When in a stopped state, no connections are possible
    // To attempt a new connection with the same client, you must call restart
    void restart();

    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(const WebSocketClient&) = delete;
    WebSocketClient(WebSocketClient&&) noexcept = delete;
    WebSocketClient& operator=(WebSocketClient&&) noexcept = delete;

private:
    std::unique_ptr<Client> m_client;
};

}
