// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <doctest/doctest.h>
#include "TestSslCtx.hpp"
#include "TestSeqCheck.hpp"

#include <fishnets/Context.hpp>
#include <fishnets/WsServerHandler.hpp>
#include <fishnets/util/WsSessionHandler.hpp>
#include <fishnets/util/ThreadRunner.hpp>
#include <fishnets/WsServe.hpp>
#include <fishnets/WsConnect.hpp>

#include <cstring>
#include <deque>
#include <optional>

constexpr uint16_t Test_Port = 7654;

struct SessionTargetFixture {
    SessionTargetFixture(std::string_view t) {
        target = t;
    }
    ~SessionTargetFixture() {
        target = "/";
    }
    static std::string target;
};
std::string SessionTargetFixture::target  = "/";

TEST_SUITE_BEGIN("fishnets");

struct Packet {
    bool istext = false;
    std::string text;
    std::vector<uint8_t> binary;

    bool operator==(std::string_view str) const {
        if (!istext) return false;
        return text == str;
    }

    bool operator==(std::span<const std::byte> bin) const {
        if (istext) return false;
        if (binary.size() != bin.size()) return false;
        return std::memcmp(binary.data(), bin.data(), binary.size()) == 0;
    }
};

const std::vector<Packet> packets = {
    Packet{true, "client 0", {}},
    Packet{true, "client 1", {}},
    Packet{false, {}, {1, 2, 3}},
    Packet{false, {}, {5, 6, 7}},
};

enum class Role {
    Client,
    Server
};

class BasicSession {
public:
    BasicSession(Role role, uint32_t id)
        : m_role(role)
        , m_id(id)
    {}

protected:
    const Role m_role = Role::Client;
    const uint32_t m_id = 0;

    ~BasicSession() = default;

    void checkOpen(std::string_view target, fishnets::EndpointInfo ep) {
        CHECK(ep.address == "127.0.0.1");
        if (m_role == Role::Client) {
            CHECK(ep.port == Test_Port);
        }
        CHECK(target == SessionTargetFixture::target);
    }
};

class TestSenderSession final : public fishnets::WsSessionHandler, public BasicSession {
    using BasicSession::BasicSession;

    void sendNext() {
        auto& packet = packets[sendIndex++];
        if (packet.istext) wsSend(packet.text);
        else wsSend(as_bytes(std::span(packet.binary)));
    }

    void closeIfDone() {
        if (sendIndex == packets.size() && receivedIndex == packets.size()) {
            wsClose();
        }
    }

    void wsOpened(std::string_view target) override {
        checkOpen(target, wsGetEndpointInfo());

        sendNext();
        wsReceive();
    }

    void wsReceivedBinary(std::span<std::byte> binary, bool complete) override {
        REQUIRE(receivedIndex < packets.size());
        CHECK(complete);
        CHECK((packets[receivedIndex] == binary));
        ++receivedIndex;
        closeIfDone();
        wsReceive();
    }

    void wsReceivedText(std::span<char> text, bool complete) override {
        REQUIRE(receivedIndex < packets.size());
        CHECK(complete);
        std::string_view str(text.data(), text.size());
        CHECK(packets[receivedIndex] == str);
        ++receivedIndex;
        closeIfDone();
        wsReceive();
    }

    void wsCompletedSend() override {
        if (sendIndex == packets.size())
        {
            closeIfDone();
            return;
        }
        sendNext();
    }

    void wsClosed(std::string) override {
        CHECK(receivedIndex == packets.size());
        CHECK(sendIndex == packets.size());
    }

    size_t sendIndex = 0;
    size_t receivedIndex = 0;
};

class TestEchoSession final : public fishnets::WsSessionHandler, public BasicSession {
    using BasicSession::BasicSession;

    void wsOpened(std::string_view target) override {
        m_seqCheck = makeSeqCheck(m_id % 2 == 1);
        checkOpen(target, wsGetEndpointInfo());
        wsReceive();
    }

    void wsReceivedBinary(std::span<std::byte> binary, bool complete) override {
        std::lock_guard l(*m_seqCheck);
        CHECK(complete);
        REQUIRE(receivedIndex < packets.size());
        CHECK((packets[receivedIndex] == binary));
        sendQueue.push_back(receivedIndex);
        ++receivedIndex;
        send();
        wsReceive();
    }

    void wsReceivedText(std::span<char> text, bool complete) override {
        std::lock_guard l(*m_seqCheck);
        CHECK(complete);
        REQUIRE(receivedIndex < packets.size());
        std::string_view str(text.data(), text.size());
        CHECK(packets[receivedIndex] == str);
        sendQueue.push_back(receivedIndex);
        ++receivedIndex;
        send();
        wsReceive();
    }

    void send() {
        if (curSend) return;
        if (sendQueue.empty()) return;
        curSend.emplace(sendQueue.front());
        sendQueue.pop_front();
        auto& packet = packets[*curSend];
        if (packet.istext) wsSend(packet.text);
        else wsSend(as_bytes(std::span(packet.binary)));
    }

    void wsCompletedSend() override {
        std::lock_guard l(*m_seqCheck);

        //if (m_id > 0) {
        //    const char* role = (m_role == Role::Client) ? "client" : "server";
        //    auto tid = std::this_thread::get_id();
        //    printf("%s %d: %d\n", role, m_id, tid);
        //}

        curSend.reset();
        send();
    }

    std::unique_ptr<SeqCheckBase> m_seqCheck;
    std::deque<size_t> sendQueue;
    std::optional<size_t> curSend;
    size_t receivedIndex = 0;
};

template <typename SessionType>
struct TestServer {
    fishnets::Context m_ctx;
    std::shared_ptr<fishnets::SslContext> m_sslCtx = createServerTestSslCtx();
    fishnets::ThreadRunner m_runner;
    uint32_t m_freeSessionId = 0;

    TestServer(size_t numThreads) {
        wsServeLocalhost(
            m_ctx,
            Test_Port,
            std::make_shared<fishnets::SimpleServerHandler>([this](const fishnets::EndpointInfo& local, const fishnets::EndpointInfo remote) {
                CHECK(local.address == "127.0.0.1");
                CHECK(local.port == Test_Port);
                CHECK(remote.address == "127.0.0.1");
                return std::make_shared<SessionType>(Role::Server, m_freeSessionId++);
            }),
            m_sslCtx.get()
        );
        m_runner.start(m_ctx, numThreads);
    }
    ~TestServer() {
        m_ctx.stop();
    }
};

struct TestClientRunParams {
    uint32_t numSessions;
    uint32_t numThreads;
};

template <typename SessionType>
void runTestClient(TestClientRunParams params) {
    fishnets::Context ctx;
    auto sslCtx = createClientTestSslCtx();
    for (uint32_t i = 0; i < params.numSessions; ++i) {
        wsConnect(
            ctx,
            std::make_shared<SessionType>(Role::Client, i),
            {"127.0.0.1", Test_Port},
            SessionTargetFixture::target,
            sslCtx.get()
        );
    }
    fishnets::ThreadRunner runner(ctx, params.numThreads);
};

TEST_CASE("simple connect") {
    TestServer<TestEchoSession> server(1);
    runTestClient<TestSenderSession>({.numSessions = 1, .numThreads = 1});
}

TEST_CASE("simple connect target") {
    SessionTargetFixture f("/xyz");

    TestServer<TestSenderSession> server(1);
    runTestClient<TestEchoSession>({.numSessions = 1, .numThreads = 1});
}

TEST_CASE("server echo multi") {
    TestServer<TestEchoSession> server(3);
    runTestClient<TestSenderSession>({.numSessions = 6, .numThreads = 3});
}

TEST_CASE("client echo multi") {
    TestServer<TestSenderSession> server(3);
    runTestClient<TestEchoSession>({.numSessions = 6, .numThreads = 3});
}
