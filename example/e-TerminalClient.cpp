// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketSession.hpp>

#include <xec/TaskExecutor.hpp>
#include <xec/ThreadExecution.hpp>

#include <atomic>
#include <iostream>
#include <queue>
#include <thread>
#include <optional>
#include <cassert>
#include <chrono>

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

    void wsClosed() override {}

    void wsReceivedBinary(itlib::memory_view<uint8_t> binary) override
    {
        std::cout << "Received binary with size " << binary.size() << '\n';
    }

    void wsReceivedText(itlib::memory_view<char> text) override
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

class App : public xec::TaskExecutor
{
public:
    App()
    {
        m_serverConnectionThread = std::thread([this]() { runServerConnectionThread(); });
    }

    // any thread
    bool active() const { return m_active.load(std::memory_order_relaxed); }

    void sendCommand(std::string cmd)
    {
        pushTask([this, cmd=std::move(cmd)]() mutable { onCommand(std::move(cmd)); });
    }

    void sessionConnected(SessionPtr session)
    {
        pushTask([this, session]() { onSessionConnected(session); });
    }

private:
    // app thread
    void onCommand(std::string command)
    {
        if (command == "/quit")
        {
            m_active.store(false, std::memory_order_relaxed);
            stop();
            if (m_currentConnectedSession)
            {
                m_currentConnectedSession->disconnect();
            }
            m_serverConnectionThread.join();
            std::cout << "App has shut down. Press <ENTER> to quit.\n";
        }
        else if (!m_currentConnectedSession)
        {
            std::cout << "No session is currently connected\n";
        }
        else
        {
            m_currentConnectedSession->send(std::move(command));
        }
    }

    void onClientDisconnected()
    {
        m_currentConnectedSession.reset();
    }

    void onSessionConnected(SessionPtr session)
    {
        assert(!m_currentConnectedSession);
        if (!active())
        {
            session->disconnect();
            return;
        }
        std::cout << "Conection to the server was established\n";
        m_currentConnectedSession = session;
    }

    // connection thrad
    void runServerConnectionThread()
    {
        while (true)
        {
            fishnets::WebSocketClient client(std::make_shared<Session>(*this), "localhost", 7654);
            pushTask([this]() { onClientDisconnected(); });
            if (active())
            {
                std::cout << "Disconnected. Trying to reconnect...\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            else
            {
                break;
            }
        }
    }

private:
    std::atomic_bool m_active = true;

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
    xec::ThreadExecution appExecution(app);
    appExecution.launchThread("App");

    while (app.active())
    {
        std::string cmd;
        std::getline(std::cin, cmd);
        app.sendCommand(std::move(cmd));
    }

    appExecution.joinThread();
    return 0;
}
