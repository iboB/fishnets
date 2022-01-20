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

#include <xec/ThreadExecution.hpp>
#include <xec/TaskExecutor.hpp>

#include <list>

TEST_SUITE_BEGIN("fishnets");

struct Packet
{
    bool istext = false;
    std::string text;
    std::vector<uint8_t> binary;
};

static constexpr size_t NUM_SESSIONS = 6;

class Object
{
public:
    Object(itlib::const_memory_view<uint8_t> data)
        : m_data(data.begin(), data.end())
    {}

    const std::vector<uint8_t>& data() const {
        return m_data;
    }
private:
    std::vector<uint8_t> m_data;
};

class Subscriber
{
public:
    virtual void ack() = 0;
    virtual void bye() = 0;
    virtual void sendObj(const Object& object) = 0;
};

class Server : public xec::TaskExecutor
{
public:
    std::vector<Object> objects;
    std::vector<std::shared_ptr<Subscriber>> subs;
    bool byesSent = false;
};

// sequencing checks
// checks that io calls are strictly sequenced
// it's an interface so as to have a noop implementation
// thus not all sessions will have sequencing checks in case these sequencing checks imrove the actual sequencing
struct SeqCheckBase
{
    virtual ~SeqCheckBase() = default;
    virtual void lock() = 0;
    virtual void unlock() = 0;
};

struct NoopSeqCheck final : SeqCheckBase
{
    virtual void lock() override {}
    virtual void unlock() override {}
};

struct StrictSeqCheck final : SeqCheckBase
{
    std::mutex mut;

    virtual void lock() override
    {
        REQUIRE(mut.try_lock());
    }

    virtual void unlock() override
    {
        mut.unlock();
    }
};

std::atomic_int32_t destroyedServerSessions = {};

class TestServerSession final : public fishnets::WebSocketSession, public Subscriber, public std::enable_shared_from_this<TestServerSession>
{
public:
    TestServerSession(Server& server, int32_t id)
        : m_server(server)
    {
        if (id % 2)
        {
            m_seqCheck.reset(new NoopSeqCheck);
        }
        else
        {
            m_seqCheck.reset(new StrictSeqCheck);
        }
    }

    ~TestServerSession()
    {
        ++destroyedServerSessions;
    }

    void wsOpened() override
    {
        std::lock_guard l(*m_seqCheck);

        m_server.pushTask([self = shared_from_this()]() {
            auto& server = self->m_server;
            server.subs.emplace_back(self);
            // send existing objects
            for (auto& obj : server.objects)
            {
                self->sendObj(obj);
            }
        });
    }

    void wsClosed() override
    {
        std::lock_guard l(*m_seqCheck);
        CHECK(m_totalSends == (NUM_SESSIONS - 1) * 5 /*obj*/ + 5 /*ack*/ + 1 /*bye*/);
        m_server.pushTask([self = shared_from_this()]() {
            auto& subs = self->m_server.subs;
            auto f = std::find(subs.begin(), subs.end(), self);
            REQUIRE(f != subs.end());
            subs.erase(f);
            if (subs.size() == 0)
            {
                CHECK(self->m_server.byesSent);
                self->m_server.stop();
            }
        });
    }

    void wsReceivedBinary(itlib::memory_view<uint8_t> binary) override
    {
        std::lock_guard l(*m_seqCheck);
        m_server.pushTask([obj = Object(binary), self = shared_from_this()]() {
            auto& server = self->m_server;
            server.objects.emplace_back(std::move(obj));
            for (auto& sub : server.subs)
            {
                if (sub == self)
                {
                    sub->ack();
                }
                else
                {
                    sub->sendObj(server.objects.back());
                }
            }
            if (server.objects.size() == NUM_SESSIONS * 5)
            {
                CHECK_FALSE(server.byesSent);
                CHECK(server.subs.size() == NUM_SESSIONS);
                for (auto& sub : server.subs)
                {
                    sub->bye();
                }
                server.byesSent = true;
            }
        });
    }

    void wsReceivedText(itlib::memory_view<char>) override
    {
        DOCTEST_FAIL("no text!");
    }

    void wsCompletedSend() override
    {
        std::lock_guard l(*m_seqCheck);
        doSend();
    }

    void doSend()
    {
        m_curPacket.reset();
        if (m_sendQueue.empty()) return;

        m_curPacket.emplace(std::move(m_sendQueue.front()));
        m_sendQueue.pop_front();

        if (m_curPacket->istext)
        {
            wsSend(m_curPacket->text);
        }
        else
        {
            wsSend(itlib::make_memory_view(m_curPacket->binary));
        }
        ++m_totalSends;
    }

    void sendPacketIOThread(Packet&& packet)
    {
        std::lock_guard l(*m_seqCheck);
        m_sendQueue.emplace_back(std::move(packet));

        if (!m_curPacket)
        {
            doSend();
        }
    }

    void ack() override
    {
        postWSIOTask([self = shared_from_this()]() {
            self->sendPacketIOThread(Packet{true, "ack", {}});
        });
    }
    void bye() override
    {
        postWSIOTask([self = shared_from_this()]() {
            self->sendPacketIOThread(Packet{true, "done", {}});
        });
    }
    void sendObj(const Object& object) override
    {
        postWSIOTask([p = Packet{false, "done", object.data()}, self = shared_from_this()]() mutable {
            self->sendPacketIOThread(std::move(p));
        });
    }

    std::list<Packet> m_sendQueue;
    std::optional<Packet> m_curPacket;
    size_t m_totalSends = 0;
    Server& m_server;
    std::unique_ptr<SeqCheckBase> m_seqCheck;
};

std::atomic_int32_t destroyedClientSessions = {};

class TestClientSession final : public fishnets::WebSocketSession
{
public:
    TestClientSession(int n)
    {
        for (int i = 0; i < 5; ++i)
        {
            std::vector<uint8_t> buf;
            for (int j = 0; j < n + 3; ++j)
            {
                buf.emplace_back(uint8_t(j));
            }
            m_objects.emplace_back(itlib::make_memory_view(buf));
        }
    }

    ~TestClientSession()
    {
        ++destroyedClientSessions;
    }

    void wsOpened() override
    {
        sendNext();
    }

    void wsClosed() override
    {
        CHECK(m_newObjects.size() == (NUM_SESSIONS - 1) * 5);
    }

    void wsReceivedBinary(itlib::memory_view<uint8_t> binary) override
    {
        m_newObjects.emplace_back(binary);
    }

    void wsReceivedText(itlib::memory_view<char> text) override
    {
        std::string_view str(text.data(), text.size());
        if (str == "ack")
            ++acks;
        else if (str == "done")
            wsClose();
    }

    void wsCompletedSend() override
    {
        if (m_sendIndex == m_objects.size()) return;
        sendNext();
    }

    void sendNext()
    {
        wsSend(itlib::make_memory_view(m_objects[m_sendIndex].data()));
        ++m_sendIndex;
    }

    std::vector<Object> m_objects;
    std::vector<Object> m_newObjects;
    size_t m_sendIndex = 0;
    int acks = 0;
};

TEST_CASE("server client threads")
{
    xec::ThreadExecutionContext executionContext;
    Server server;
    server.setExecutionContext(executionContext);

    static constexpr uint16_t port = 7654;
    std::atomic_int32_t freeServerSessionId = {};
    fishnets::WebSocketServer wsServer([&server, &freeServerSessionId](const fishnets::WebSocketEndpointInfo&) -> fishnets::WebSocketSessionPtr {
        return std::make_shared<TestServerSession>(server, int32_t(freeServerSessionId++));
    }, port, 3, testServerSSLSettings.get());


    std::vector<std::thread> wsClientThreads;
    for (int i = 0; i < int(NUM_SESSIONS); ++i)
    {
        wsClientThreads.emplace_back([i]() {
            fishnets::WebSocketClient client(
                std::make_shared<TestClientSession>(i),
                "localhost",
                port,
                testClientSSLSettings.get());
        });
    }

    server.setFinishTasksOnExit(true);
    while (executionContext.running())
    {
        executionContext.wait();
        server.update();
    }
    server.finalize();

    for (auto& t : wsClientThreads)
    {
        t.join();
    }

    CHECK(server.subs.empty());
    CHECK(destroyedServerSessions == NUM_SESSIONS);
    CHECK(destroyedClientSessions == NUM_SESSIONS);
}
