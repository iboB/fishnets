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
#include <fishnets/WebSocketSessionOptions.hpp>

#include <mutex>
#include <thread>
#include <cstring>
#include <queue>
#include <atomic>

constexpr uint16_t Test_Port = 7654;

class BasicSession : public fishnets::WebSocketSession
{
public:
    void wsReceivedBinary(itlib::span<uint8_t> binary) override
    {
        REQUIRE(binary.size() == sizeof(Packet));
        memcpy(&m_received.emplace_back(), binary.data(), sizeof(Packet));
    }

    void sendNext()
    {
        REQUIRE(!m_outQueue.empty());
        REQUIRE(!m_curOutPacket);
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
    std::queue<Packet> m_outQueue;
    std::optional<Packet> m_curOutPacket;

    std::vector<Packet> m_received;

    void send(Packet packet)
    {
        m_outQueue.push(packet);
        if (m_curOutPacket) return; // we alrady have stuff going on
        sendNext();
    }

    struct SenderEntry
    {
        fishnets::WebSocketSessionPtr (*make)(const fishnets::WebSocketEndpointInfo&);
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

class SimpleSender : public BasicSession
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    void wsOpened() override
    {
        send({Packet::Type::Id, id});
    }

    fishnets::WebSocketSessionOptions getInitialOptions() override
    {
        fishnets::WebSocketSessionOptions ret;
        ret.heartbeatInterval = std::chrono::milliseconds(100);
        return ret;
    }

    void wsHeartbeat(uint32_t ms) override
    {
        ++m_beats;
        CHECK(ms == 100);
        CHECK(m_beats < 7);
        if (m_beats < 6)
        {
            send({Packet::Type::Heartbeat, m_beats});
        }
        else
        {
            send({Packet::Type::Done, 0});
        }
    }

    static void test(const std::vector<Packet>&)
    {

    }
};

class ManualHBSender : public SimpleSender
{
public:
    DECL_SENDER();

    uint32_t m_beats = 0;

    void wsOpened() override
    {
        send({Packet::Type::Id, id});

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

    static void test(const std::vector<Packet>&)
    {

    }
};

static std::mutex g_resultMutex;
using CaseResultVec = std::vector<std::vector<BasicSession::Packet>>;
CaseResultVec* g_caseResult;

struct ReceiverSession : public BasicSession
{
    ~ReceiverSession()
    {
        std::lock_guard l(g_resultMutex);
        REQUIRE(g_caseResult);
        g_caseResult->push_back(std::move(m_received));
    }
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

        REQUIRE(m_result.size() == BasicSession::senderRegistry.size());

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
            CHECK(r.front().type == BasicSession::Packet::Type::Id);
            CHECK(r.front().payload == uint32_t(i));
            BasicSession::senderRegistry[i].testResult(r);
        }
    }
};

fishnets::WebSocketSessionPtr Make_ReceiverSession(const fishnets::WebSocketEndpointInfo&)
{
    return std::make_shared<ReceiverSession>();
}

DEF_SENDER(SimpleSender);
DEF_SENDER(ManualHBSender);

TEST_CASE("Client heartbeat")
{
    CaseResultChecker checker;

    {
        fishnets::WebSocketServer server(Make_ReceiverSession, Test_Port, 2, testServerSSLSettings.get());

        std::vector<std::thread> clients;
        for (auto& ts : BasicSession::senderRegistry)
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
        std::atomic_size_t c = {};
        fishnets::WebSocketServer server([&c](const fishnets::WebSocketEndpointInfo& info) {
            auto i = c.fetch_add(1);
            REQUIRE(i < BasicSession::senderRegistry.size());
            return BasicSession::senderRegistry[i].make(info);
        }, Test_Port, 2, testServerSSLSettings.get());

        std::vector<std::thread> clients;
        for (size_t i=0; i<BasicSession::senderRegistry.size(); ++i)
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