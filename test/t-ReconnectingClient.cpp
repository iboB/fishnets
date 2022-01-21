// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#include <doctest/doctest.h>
#include "TestSSLSettings.hpp"

#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketServer.hpp>
#include <fishnets/WebSocketSession.hpp>

#include <atomic>
#include <thread>

TEST_SUITE_BEGIN("fishnets");

static constexpr uint16_t Test_Port = 7655;

class TestClientSession final : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
        wsSend("hello");
    }
    void wsClosed() override {}
    void wsReceivedBinary(itlib::memory_view<uint8_t>) override {}
    void wsReceivedText(itlib::memory_view<char>) override {}
    void wsCompletedSend() override {}
};

class ClientConnectionManager {
public:
    ClientConnectionManager()
        : m_client(
            [](const fishnets::WebSocketEndpointInfo&) { return std::make_shared<TestClientSession>(); },
            testClientSSLSettings.get())
    {}

    int numAttempts() const { return m_numAttempts.load(std::memory_order_relaxed); }

    void start()
    {
        m_running.store(true, std::memory_order_release);
        m_ioThread = std::thread([this]() { ioThread(); });
    }

    void stop()
    {
        m_running.store(false, std::memory_order_release);
        m_client.stop();
        m_ioThread.join();
    }

    void ioThread()
    {
        while (m_running.load(std::memory_order_acquire))
        {
            m_numAttempts.fetch_add(1, std::memory_order_relaxed);
            m_client.connect("localhost", Test_Port);
            m_client.restart();
        }
    }

private:
    std::atomic_int m_numAttempts = {};
    std::atomic_bool m_running;

    std::thread m_ioThread;
    fishnets::WebSocketClient m_client;
};

TEST_CASE("failing client")
{
    ClientConnectionManager manager;
    manager.start();
    while (manager.numAttempts() < 3);
    manager.stop();
}

std::atomic_int32_t openedServerSessions = {};
std::atomic_int32_t serverReceivedPackets = {};

class TestServerSession final : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
        ++openedServerSessions;
    }
    void wsClosed() override {}
    void wsReceivedBinary(itlib::memory_view<uint8_t>) override {}
    void wsReceivedText(itlib::memory_view<char> buf) override
    {
        ++serverReceivedPackets;
        std::string_view str(buf.data(), buf.size());
        CHECK(str == "hello");
        wsClose();
    }
    void wsCompletedSend() override {}
};

TEST_CASE("connecting client")
{
    {
        fishnets::WebSocketServer server(
            [](const fishnets::WebSocketEndpointInfo&) { return std::make_shared<TestServerSession>(); },
            Test_Port,
            2,
            testServerSSLSettings.get()
        );

        ClientConnectionManager manager;
        manager.start();
        while (manager.numAttempts() < 4);
        manager.stop();
    }

    CHECK(openedServerSessions >= 3);
    CHECK(serverReceivedPackets == openedServerSessions);
}