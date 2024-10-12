// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <doctest/doctest.h>
#include "TestSSLSettings.hpp"

#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketServer.hpp>
#include <fishnets/WebSocketSession.hpp>
#include <fishnets/WebSocketSessionOptions.hpp>

#include <mutex>
#include <thread>
#include <cstring>
#include <queue>
#include <atomic>
#include <algorithm>

constexpr uint16_t Test_Port = 7654;

struct SessionPacket
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

class BasicSender : public fishnets::WebSocketSession
{
public:
    fishnets::WebSocketSessionOptions getInitialOptions() final override
    {
        fishnets::WebSocketSessionOptions ret;
        ret.heartbeatInterval = std::chrono::milliseconds(100);
        return ret;
    }

    void sendNext()
    {
        REQUIRE(!m_outQueue.empty());
        REQUIRE(!m_curOutSessionPacket);
        m_curOutSessionPacket.emplace(std::move(m_outQueue.front()));
        m_outQueue.pop();

        if (m_curOutSessionPacket->type == SessionPacket::Type::Done)
        {
            wsClose();
            return;
        }
        wsSend(itlib::span(reinterpret_cast<const uint8_t*>(&m_curOutSessionPacket.value()), sizeof(SessionPacket)));
    }

    void wsCompletedSend() override
    {
        m_curOutSessionPacket.reset();
        if (m_outQueue.empty()) return; // nothing to do
        sendNext();
    }

    std::queue<SessionPacket> m_outQueue;
    std::optional<SessionPacket> m_curOutSessionPacket;

    void send(SessionPacket packet)
    {
        m_outQueue.push(packet);
        if (m_curOutSessionPacket) return; // we alrady have stuff going on
        sendNext();
    }

    struct SenderEntry
    {
        fishnets::WebSocketSessionPtr (*make)(const fishnets::WebSocketEndpointInfo&);
        void (*testResult)(const std::vector<SessionPacket>& result);
    };
    static std::vector<SenderEntry> senderRegistry;

    template <typename Sender>
    static uint32_t registerSender()
    {
        senderRegistry.push_back({&Sender::make, &Sender::test});
        return uint32_t(senderRegistry.size() - 1);
    }
};

std::vector<BasicSender::SenderEntry> BasicSender::senderRegistry;

#define DECL_SENDER() \
    static const uint32_t id; \
    static fishnets::WebSocketSessionPtr make(const fishnets::WebSocketEndpointInfo&)

#define DEF_SENDER(T) \
    fishnets::WebSocketSessionPtr T::make(const fishnets::WebSocketEndpointInfo&) \
    { \
        return std::make_shared<T>(); \
    } \
    const uint32_t T::id = BasicSender::registerSender<T>()

class SimpleSender final : public BasicSender
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    void wsOpened() override
    {
        send({SessionPacket::Type::Id, id});
    }

    void wsHeartbeat(uint32_t ms) override
    {
        ++m_beats;
        CHECK(ms == 100);
        CHECK(m_beats < 7);
        if (m_beats < 6)
        {
            send({SessionPacket::Type::Heartbeat, m_beats});
        }
        else
        {
            send({SessionPacket::Type::Done, 0});
        }
    }

    static void test(const std::vector<SessionPacket>& r)
    {
        REQUIRE(r.size() == 6);
        for (uint32_t i = 1; i < 6; ++i)
        {
            auto& p = r[i];
            CHECK(p.type == SessionPacket::Type::Heartbeat);
            CHECK(p.payload == i);
        }
    }
};

class ManualHBSender final : public BasicSender
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    void wsOpened() override
    {
        send({SessionPacket::Type::Id, id});

        fishnets::WebSocketSessionOptions opts;
        opts.heartbeatInterval = std::chrono::milliseconds(90);
        wsSetOptions(opts);
    }

    void wsHeartbeat(uint32_t ms) override
    {
        ++m_beats;
        CHECK(ms == 90);
        CHECK(m_beats < 7);
        if (m_beats < 6)
        {
            send({SessionPacket::Type::Heartbeat, m_beats});
        }
        else
        {
            send({SessionPacket::Type::Done, 0});

            fishnets::WebSocketSessionOptions opts;
            opts.heartbeatInterval = std::chrono::milliseconds(0);
            wsSetOptions(opts);
        }
    }

    static void test(const std::vector<SessionPacket>& r)
    {
        REQUIRE(r.size() == 6);
        for (uint32_t i = 1; i < 6; ++i)
        {
            auto& p = r[i];
            CHECK(p.type == SessionPacket::Type::Heartbeat);
            CHECK(p.payload == i);
        }
    }
};

class RestartSender final : public BasicSender
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    void wsOpened() override
    {
        send({SessionPacket::Type::Id, id});

        fishnets::WebSocketSessionOptions opts;
        opts.heartbeatInterval = std::chrono::milliseconds(50);
        wsSetOptions(opts);
    }

    void wsHeartbeat(uint32_t ms) override
    {
        ++m_beats;
        CHECK(m_beats < 7);

        if (ms == 50)
        {
            send({SessionPacket::Type::Heartbeat, m_beats * 10});
            if (m_beats == 3)
            {
                fishnets::WebSocketSessionOptions opts;
                opts.heartbeatInterval = std::chrono::milliseconds(0);
                wsSetOptions(opts);
            }
        }
        else
        {
            CHECK(ms == 150);
            send({SessionPacket::Type::Heartbeat, m_beats * 100});
            if (m_beats == 6)
            {
                send({SessionPacket::Type::Done, 0});
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
        BasicSender::wsCompletedSend();
    }

    static void test(const std::vector<SessionPacket>& r)
    {
        REQUIRE(r.size() == 7);
        for (uint32_t i = 1; i < 4; ++i)
        {
            auto& p = r[i];
            CHECK(p.type == SessionPacket::Type::Heartbeat);
            CHECK(p.payload == i * 10);
        }
        for (uint32_t i = 4; i < 6; ++i)
        {
            auto& p = r[i];
            CHECK(p.type == SessionPacket::Type::Heartbeat);
            CHECK(p.payload == i * 100);
        }
    }
};

static std::mutex g_resultMutex;
using CaseResultVec = std::vector<std::vector<SessionPacket>>;
CaseResultVec* g_caseResult;

struct ReceiverSession final : public fishnets::WebSocketSession
{
    void wsReceivedBinary(itlib::span<uint8_t> binary) final override
    {
        REQUIRE(binary.size() == sizeof(SessionPacket));
        memcpy(&m_received.emplace_back(), binary.data(), sizeof(SessionPacket));
    }

    ~ReceiverSession()
    {
        std::lock_guard l(g_resultMutex);
        REQUIRE(g_caseResult);
        g_caseResult->push_back(std::move(m_received));
    }

    std::vector<SessionPacket> m_received;
};

class CaseResultChecker
{
    CaseResultVec m_result;
public:
    CaseResultChecker()
    {
        REQUIRE(!g_caseResult);
        g_caseResult = &m_result;
    }
    ~CaseResultChecker()
    {
        REQUIRE(!!g_caseResult);
        g_caseResult = nullptr;

        REQUIRE(m_result.size() == BasicSender::senderRegistry.size());

        for (auto& r : m_result)
        {
            REQUIRE(!r.empty());
        }

        std::sort(m_result.begin(), m_result.end(), [](auto& a, auto& b) {
            return a.front().payload < b.front().payload;
        });

        for (size_t i=0; i<m_result.size(); ++i)
        {
            auto& r = m_result[i];
            CHECK(r.front().type == SessionPacket::Type::Id);
            CHECK(r.front().payload == uint32_t(i));
            BasicSender::senderRegistry[i].testResult(r);
        }
    }
};

fishnets::WebSocketSessionPtr Make_ReceiverSession(const fishnets::WebSocketEndpointInfo&)
{
    return std::make_shared<ReceiverSession>();
}

DEF_SENDER(SimpleSender);
DEF_SENDER(ManualHBSender);
DEF_SENDER(RestartSender);

TEST_CASE("Client heartbeat")
{
    CaseResultChecker checker;

    {
        fishnets::WebSocketServer server(Make_ReceiverSession, Test_Port, 2, testServerSSLSettings.get());

        std::vector<std::thread> clients;
        for (auto& ts : BasicSender::senderRegistry)
        {
            clients.emplace_back([&]() {
                fishnets::WebSocketClient client(ts.make, testClientSSLSettings.get());
                client.connect("localhost", Test_Port);
            });
        }
        for (auto& c : clients)
        {
            c.join();
        }
    }
}

TEST_CASE("Server heartbeat")
{
    CaseResultChecker checker;

    {
        std::atomic_size_t cnt = {};
        fishnets::WebSocketServer server([&cnt](const fishnets::WebSocketEndpointInfo& info) {
            auto i = cnt.fetch_add(1);
            REQUIRE(i < BasicSender::senderRegistry.size());
            return BasicSender::senderRegistry[i].make(info);
        }, Test_Port, 2, testServerSSLSettings.get());

        std::vector<std::thread> clients;
        for (size_t i=0; i < BasicSender::senderRegistry.size(); ++i)
        {
            clients.emplace_back([&]() {
                fishnets::WebSocketClient client(Make_ReceiverSession, testClientSSLSettings.get());
                client.connect("localhost", Test_Port);
            });
        }
        for (auto& c : clients)
        {
            c.join();
        }
    }
}
