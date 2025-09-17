// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/Context.hpp>
#include <fishnets/util/WsSessionHandler.hpp>
#include <fishnets/WsConnect.hpp>

#include <atomic>
#include <iostream>
#include <queue>
#include <thread>
#include <cassert>


class Session final : public fishnets::WsSessionHandler
{
public:
    std::atomic_bool active = true;

    void send(std::string text) {
        postWsIoTask([this, text = std::move(text)]() mutable {
            if (text == "/exit") {
                wsClose();
            }
            else {
                onSend(std::move(text));
            }
        });
    }

private:
    void onSend(std::string text) {
        m_queue.emplace(std::move(text));
        if (m_curPacket) return; // we already have stuff going on
        sendNext();
    }

    void sendNext() {
        assert(!m_queue.empty());
        assert(!m_curPacket);
        m_curPacket.emplace(std::move(m_queue.front()));
        m_queue.pop();
        wsSend(*m_curPacket);
    }

    void wsOpened(std::string_view) override {
        wsReceive();
    }

    void wsClosed(std::string reason) override {
        std::cout << "Connection closed: " << reason << '\n';
        active = false;
    }

    void wsReceivedBinary(std::span<uint8_t> binary, bool) override {
        std::cout << "Received binary with size " << binary.size() << '\n';
        wsReceive();
    }

    void wsReceivedText(std::span<char> text, bool) override {
        std::string_view str(text.data(), text.size());
        std::cout << "Received text " << str << '\n';
        wsReceive();
    }

    void wsCompletedSend() override {
        m_curPacket.reset();
        if (m_queue.empty()) return; // nothing to do
        sendNext();
    }

    std::queue<std::string> m_queue;
    std::optional<std::string> m_curPacket;
};

int main()
{
    fishnets::Context ctx;
    auto session = std::make_shared<Session>();

    wsConnect(ctx, session, "ws://localhost:7654");

    std::thread t([&ctx] {
        ctx.run();
    });

    while (session->active) {
        std::string cmd;
        std::getline(std::cin, cmd);
        session->send(std::move(cmd));
    }

    t.join();
    return 0;
}
