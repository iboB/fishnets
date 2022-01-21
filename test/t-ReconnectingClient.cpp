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
#include <mutex>

TEST_SUITE_BEGIN("fishnets");

static constexpr uint16_t Test_Port = 7655;

class TestClientSession final : public fishnets::WebSocketSession
{
    void wsOpened() override {}
    void wsClosed() override {}
    void wsReceivedBinary(itlib::memory_view<uint8_t>) override {}
    void wsReceivedText(itlib::memory_view<char>) override {}
    void wsCompletedSend() override {}
};

class ClientConnectionManager {
public:
    int numAttempts() const { return m_numAttempts.load(std::memory_order_relaxed); }

    void start()
    {
        m_session = std::make_shared<TestClientSession>();
        m_ioThread = std::thread([this]() { ioThread(); });
    }

    void stop()
    {
        m_ioThread.join();
    }

    void ioThread()
    {
        while (true)
        {

        }
    }

private:
    std::atomic_int m_numAttempts = {};
    std::atomic_bool m_running;

    std::thread m_ioThread;

    std::mutex m_sessionMutex;
    std::shared_ptr<TestClientSession> m_session;
};

TEST_CASE("failing client")
{
}

