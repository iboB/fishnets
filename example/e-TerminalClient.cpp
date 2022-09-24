// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketSession.hpp>

#include <atomic>
#include <iostream>
#include <queue>
#include <thread>
#include <optional>
#include <cassert>
#include <chrono>
#include <mutex>

class App;

class Session final : public fishnets::WebSocketSession, public std::enable_shared_from_this<Session>
{
public:
    Session(App& app) : m_app(app) {}

    void send(std::string text)
    {
        postWSIOTask([this, text = std::move(text)]() mutable {
            onSend(std::move(text));
        });
    }

    void disconnect()
    {
        postWSIOTask([this]() {
            wsClose();
        });
    }
private:
    void onSend(std::string text)
    {
        m_queue.emplace(std::move(text));
        if (m_curPacket) return; // we alrady have stuff going on
        sendNext();
    }

    void sendNext()
    {
        assert(!m_queue.empty());
        assert(!m_curPacket);
        m_curPacket.emplace(std::move(m_queue.front()));
        m_queue.pop();
        wsSend(*m_curPacket);
    }

    void wsOpened() override; // defined below as it depends on the app

    void wsReceivedBinary(itlib::span<uint8_t> binary) override
    {
        std::cout << "Received binary with size " << binary.size() << '\n';
    }

    void wsReceivedText(itlib::span<char> text) override
    {
        std::string_view str(text.data(), text.size());
        std::cout << "Received text " << str << '\n';
    }

    void wsCompletedSend() override
    {
        m_curPacket.reset();
        if (m_queue.empty()) return; // nothing to do
        sendNext();
    }

    App& m_app;

    std::queue<std::string> m_queue;
    std::optional<std::string> m_curPacket;
};

using SessionPtr = std::shared_ptr<Session>;

class App
{
public:
    App()
    {
        m_client.emplace([this](const fishnets::WebSocketEndpointInfo&) {
            return std::make_shared<Session>(*this);
        });
        m_serverConnectionThread = std::thread([this]() { runServerConnectionThread(); });
    }

    // any thread
    bool active() const { return m_active.load(std::memory_order_acquire); }

    void sendCommand(std::string cmd)
    {
        if (cmd == "/quit")
        {
            m_active.store(false, std::memory_order_release);
            m_client->stop();
            m_serverConnectionThread.join();
            std::cout << "App has shut down. Press <ENTER> to quit.\n";
            return;
        }

        std::lock_guard l(m_sessionMutex);
        if (!m_currentConnectedSession)
        {
            std::cout << "No session is currently connected\n";
        }
        else
        {
            m_currentConnectedSession->send(std::move(cmd));
        }
    }

    void sessionConnected(SessionPtr session)
    {
        std::cout << "Conection to the server was established\n";
        std::lock_guard l(m_sessionMutex);
        m_currentConnectedSession = session;
    }

private:

    void onSessionDisconnected()
    {
        std::lock_guard l(m_sessionMutex);
        m_currentConnectedSession.reset();
    }

    // connection thrad
    void runServerConnectionThread()
    {
        while (active())
        {
            m_client->connect("localhost", 7654);
            onSessionDisconnected();
            std::cout << "Disconnected. Trying to reconnect...\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            m_client->restart();
        }
    }

private:
    std::atomic_bool m_active = true;

    std::optional<fishnets::WebSocketClient> m_client;

    std::mutex m_sessionMutex;
    SessionPtr m_currentConnectedSession;

    std::thread m_serverConnectionThread;
};

void Session::wsOpened()
{
    m_app.sessionConnected(shared_from_this());
}

int main()
{
    App app;

    while (app.active())
    {
        std::string cmd;
        std::getline(std::cin, cmd);
        app.sendCommand(std::move(cmd));
    }

    return 0;
}
