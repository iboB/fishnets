// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketServer.hpp>
#include <fishnets/WebSocketSession.hpp>
#include <fishnets/WebSocketSessionOptions.hpp>
#include <fishnets/WsSessionHandler.hpp>

#include <mutex>
#include <thread>
#include <cstring>
#include <queue>
#include <atomic>
#include <cassert>

constexpr uint16_t Test_Port = 7654;

struct Packet
{
    enum class Type : uint32_t {
        Unknown,
        Id,
        Heartbeat,
        Done,
    };
    Type type = Type::Unknown;
    uint32_t payload = 0;
};

class BasicSession : public fishnets::WebSocketSession
{
public:
    void sendNext()
    {
        assert(!m_outQueue.empty());
        assert(!m_curOutPacket);
        m_curOutPacket.emplace(std::move(m_outQueue.front()));
        m_outQueue.pop();

        if (m_curOutPacket->type == Packet::Type::Done)
        {
            wsClose();
            return;
        }
        wsSend(itlib::span(reinterpret_cast<const uint8_t*>(&m_curOutPacket.value()), sizeof(Packet)));
    }

    void wsCompletedSend() override
    {
        m_curOutPacket.reset();
        if (m_outQueue.empty()) return; // nothing to do
        sendNext();
    }

    std::queue<Packet> m_outQueue;
    std::optional<Packet> m_curOutPacket;

    void send(Packet packet)
    {
        m_outQueue.push(packet);
        if (m_curOutPacket) return; // we alrady have stuff going on
        sendNext();
    }

    struct SenderEntry
    {
        fishnets::WebSocketSessionPtr(*make)(const fishnets::WebSocketEndpointInfo&);
        void (*testResult)(const std::vector<Packet>& result);
    };
    static std::vector<SenderEntry> senderRegistry;

    template <typename Sender>
    static uint32_t registerSender()
    {
        senderRegistry.push_back({&Sender::make, &Sender::test});
        return uint32_t(senderRegistry.size() - 1);
    }
};

std::vector<BasicSession::SenderEntry> BasicSession::senderRegistry;

#define DECL_SENDER() \
    static const uint32_t id; \
    static fishnets::WebSocketSessionPtr make(const fishnets::WebSocketEndpointInfo&)

#define DEF_SENDER(T) \
    fishnets::WebSocketSessionPtr T::make(const fishnets::WebSocketEndpointInfo&) \
    { \
        return std::make_shared<T>(); \
    } \
    const uint32_t T::id = BasicSession::registerSender<T>()

class BasicSender : public BasicSession
{
public:
    fishnets::WebSocketSessionOptions getInitialOptions() final override
    {
        fishnets::WebSocketSessionOptions ret;
        ret.heartbeatInterval = std::chrono::milliseconds(100);
        return ret;
    }
};

class SimpleSender final : public BasicSender
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    itlib::span<uint8_t> wsOpened() override
    {
        send({Packet::Type::Id, id});
        return {};
    }

    void wsHeartbeat(uint32_t ms) override
    {
        ++m_beats;
        assert(ms == 100);
        assert(m_beats < 7);
        if (m_beats < 6)
        {
            send({Packet::Type::Heartbeat, m_beats});
        }
        else
        {
            send({Packet::Type::Done, 0});
        }
    }

    static void test(const std::vector<Packet>& r)
    {
        assert(r.size() == 6);
        for (uint32_t i = 1; i < 6; ++i)
        {
            auto& p = r[i];
            assert(p.type == Packet::Type::Heartbeat);
            assert(p.payload == i);
        }
    }
};

class ManualHBSender final : public BasicSender
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    itlib::span<uint8_t> wsOpened() override
    {
        send({Packet::Type::Id, id});

        fishnets::WebSocketSessionOptions opts;
        opts.heartbeatInterval = std::chrono::milliseconds(90);
        wsSetOptions(opts);
        return {};
    }

    void wsHeartbeat(uint32_t ms) override
    {
        ++m_beats;
        assert(ms == 90);
        assert(m_beats < 7);
        if (m_beats < 6)
        {
            send({Packet::Type::Heartbeat, m_beats});
        }
        else
        {
            send({Packet::Type::Done, 0});

            fishnets::WebSocketSessionOptions opts;
            opts.heartbeatInterval = std::chrono::milliseconds(0);
            wsSetOptions(opts);
        }
    }

    static void test(const std::vector<Packet>& r)
    {
        assert(r.size() == 6);
        for (uint32_t i = 1; i < 6; ++i)
        {
            auto& p = r[i];
            assert(p.type == Packet::Type::Heartbeat);
            assert(p.payload == i);
        }
    }
};

class RestartSender final : public BasicSender
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    itlib::span<uint8_t> wsOpened() override
    {
        send({Packet::Type::Id, id});

        fishnets::WebSocketSessionOptions opts;
        opts.heartbeatInterval = std::chrono::milliseconds(50);
        wsSetOptions(opts);

        return {};
    }

    void wsHeartbeat(uint32_t ms) override
    {
        ++m_beats;
        assert(m_beats < 7);

        if (ms == 50)
        {
            send({Packet::Type::Heartbeat, m_beats * 10});
            if (m_beats == 3)
            {
                fishnets::WebSocketSessionOptions opts;
                opts.heartbeatInterval = std::chrono::milliseconds(0);
                wsSetOptions(opts);
            }
        }
        else
        {
            assert(ms == 150);
            send({Packet::Type::Heartbeat, m_beats * 100});
            if (m_beats == 6)
            {
                send({Packet::Type::Done, 0});
            }
        }
    }

    void wsCompletedSend() override
    {
        if (m_outQueue.empty() && m_beats == 3)
        {
            fishnets::WebSocketSessionOptions opts;
            opts.heartbeatInterval = std::chrono::milliseconds(150);
            wsSetOptions(opts);
        }
        BasicSession::wsCompletedSend();
    }

    static void test(const std::vector<Packet>& r)
    {
        assert(r.size() == 7);
        for (uint32_t i = 1; i < 4; ++i)
        {
            auto& p = r[i];
            assert(p.type == Packet::Type::Heartbeat);
            assert(p.payload == i * 10);
        }
        for (uint32_t i = 4; i < 6; ++i)
        {
            auto& p = r[i];
            assert(p.type == Packet::Type::Heartbeat);
            assert(p.payload == i * 100);
        }
    }
};

struct ReceiverSession final : public fishnets::WebSocketSession
{};

fishnets::WebSocketSessionPtr Make_ReceiverSession(const fishnets::WebSocketEndpointInfo&)
{
    return std::make_shared<ReceiverSession>();
}

DEF_SENDER(SimpleSender);
DEF_SENDER(ManualHBSender);
DEF_SENDER(RestartSender);

int main()
{
    fishnets::WebSocketServer server(Make_ReceiverSession, Test_Port, 2);

    std::vector<std::thread> clients;
    for (auto& ts : BasicSession::senderRegistry)
    {
        clients.emplace_back([&]() {
            fishnets::WebSocketClient client(ts.make);
            client.connect("localhost", Test_Port);
        });
    }
    for (auto& c : clients)
    {
        c.join();
    }
}
