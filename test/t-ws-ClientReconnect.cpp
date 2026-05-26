// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <doctest/doctest.h>
#include <doctest/util/random.hpp>
#include "TestSslCtx.hpp"

#include <fishnets/WsServerHandler.hpp>
#include <fishnets/util/WsSessionHandlerWithSendQueue.hpp>
#include <fishnets/WsServe.hpp>
#include <fishnets/WsConnect.hpp>

#include <xeq/context.hpp>
#include <xeq/thread_runner.hpp>

#include <latch>
#include <chrono>
#include <algorithm>

constexpr uint16_t Accept_Port = 7654;
constexpr uint16_t Deny_Port = 7655;

class EchoSession final : public fishnets::WsSessionHandlerWithSendQueue {
    void wsOpened(std::string_view) override {
        wsSetAutoReceive(true);
        wsReceive();
    }
    void wsReceivedBinary(std::span<std::byte> binary, bool complete) override {
        REQUIRE(complete);
        wsAddToSendQueue(BinaryBufferType(binary.begin(), binary.end()));
    }
    void wsReceivedText(std::span<char> text, bool complete) override {
        REQUIRE(complete);
        auto str = std::string(text.begin(), text.end());
        if (str == "remote-close") {
            wsClose();
        }
        else if (str == "remote-expire") {
            wsSetAutoReceive(false);
        }
        else {
            wsAddToSendQueue(std::move(str));
        }
    }
};

struct EchoServer {
    xeq::context m_ctx;
    std::shared_ptr<fishnets::SslContext> m_sslCtx = createServerTestSslCtx();
    xeq::thread_runner m_runner;

    EchoServer(size_t numThreads) {
        wsServeLocalhost(
            m_ctx,
            Accept_Port,
            std::make_shared<fishnets::SimpleServerHandler>([](fishnets::WsServerConnectionPtr c) {
                c->accept(std::make_shared<EchoSession>());
            }),
            m_sslCtx.get()
        );
        wsServeLocalhost(
            m_ctx,
            Deny_Port,
            std::make_shared<fishnets::SimpleServerHandler>([](fishnets::WsServerConnectionPtr c) {
                auto t = std::chrono::steady_clock::now().time_since_epoch().count();
                // actively reject about 1/2 of the session
                // auto (passively, by virtue of expire) reject the others
                if (t % 2 == 0) {
                    c->reject();
                }
            }),
            m_sslCtx.get()
        );
        m_runner.start(m_ctx, numThreads);
    }
    ~EchoServer() {
        m_ctx.stop();
    }
};


class TestSession : public fishnets::WsSessionHandler {
public:
    std::deque<std::string> m_queue;
    const int m_expectedStatus = 0;

    // will either contain the number of frames sent
    // or -1 on connection error
    int status = 0;

    TestSession(std::deque<std::string> queue, int expectedStatus)
        : m_queue(std::move(queue))
        , m_expectedStatus(expectedStatus)
    {}

    ~TestSession() {
        CHECK(status == m_expectedStatus);
    }

    void onConnectionError(std::string) final override {
        CHECK(status == 0);
        status = -1;
    }

    void wsOpened(std::string_view) final override {
        wsSetAutoReceive(true);
        wsReceive();

        wsSend(m_queue.front());
    }

    void wsReceivedText(std::span<char> text, bool complete) final override {
        REQUIRE(complete);
        std::string_view str(text.data(), text.size());
        CHECK(str == m_queue.front());
        m_queue.pop_front();

        const auto& newFront = m_queue.front();
        if (newFront == "local-close") {
            wsClose();
        }
        else if (newFront == "local-expire") {
            wsSetAutoReceive(false);
        }
        else {
            wsSend(newFront);
        }
    }

    void wsCompletedSend() final override {
        ++status;
    }
};

struct TestScenario {
    std::deque<std::string> queue;
    uint16_t port;
    int expectedStatus;
};

using TestScenarioVec = std::vector<TestScenario>;
const TestScenarioVec g_scenarios = {
    {{"hello", "world", "local-close", "what"}, Accept_Port, 2},
    {{"howdy", "remote-close", "o_O"}, Accept_Port, 2},
    {{"nope"}, Deny_Port, -1},
    {{"another", "local-close", "nej"}, Accept_Port, 1},
    {{"it's-a", "me", "Mario", "remote-expire", "nyet"}, Accept_Port, 4},
    {{"nein"}, Deny_Port, -1},
    {{"will expire", "local-expire", "yok"}, Accept_Port, 1},
    {{"last one", "i promise", "remote-close", "oxi"}, Accept_Port, 3},
};

TEST_CASE("context-based") {
    auto seed = GET_RANDOM_DEVICE_SEED("context-based");
    std::mt19937 rng(seed);
    auto scenarios = g_scenarios;
    std::shuffle(scenarios.begin(), scenarios.end(), rng);

    EchoServer server(2);

    xeq::context ctx;
    auto sslCtx = createClientTestSslCtx();

    for (const auto& s : scenarios) {
        wsConnect(
            ctx,
            std::make_shared<TestSession>(s.queue, s.expectedStatus),
            {"127.0.0.1", s.port},
            "/",
            sslCtx.get()
        );
        ctx.run();
        ctx.restart();
    }
}

class SelfReconnectTestSession : public TestSession {
public:
    xeq::context& m_ctx;
    fishnets::SslContext* m_sslCtx;
    TestScenarioVec& m_scenarios;
    std::latch& m_latch;

    SelfReconnectTestSession(xeq::context& ctx, fishnets::SslContext* sslCtx, TestScenarioVec& scenarios, std::latch& latch)
        : TestSession(scenarios.back().queue, scenarios.back().expectedStatus)
        , m_ctx(ctx)
        , m_sslCtx(sslCtx)
        , m_scenarios(scenarios)
        , m_latch(latch)
    {}

    ~SelfReconnectTestSession() {
        m_scenarios.pop_back();
        if (m_scenarios.empty()) {
            m_latch.count_down();
            return;
        }
        std::make_shared<SelfReconnectTestSession>(m_ctx, m_sslCtx, m_scenarios, m_latch)->connect();
    }

    void connect() {
        wsConnect(
            m_ctx,
            shared_from(this),
            {"127.0.0.1", m_scenarios.back().port},
            "/",
            m_sslCtx
        );
    }
};

TEST_CASE("ctx-share") {
    auto seed = GET_RANDOM_DEVICE_SEED("ctx-share");
    std::mt19937 rng(seed);
    auto scenariosA = g_scenarios;
    std::shuffle(scenariosA.begin(), scenariosA.end(), rng);
    auto scenariosB = g_scenarios;
    std::shuffle(scenariosB.begin(), scenariosB.end(), rng);

    EchoServer server(2);

    xeq::context ctx;
    auto wg = ctx.make_work_guard();
    xeq::thread_runner runner(ctx, 3);

    auto sslCtx = createClientTestSslCtx();

    std::latch latch(2);

    std::make_shared<SelfReconnectTestSession>(ctx, sslCtx.get(), scenariosA, latch)->connect();
    std::make_shared<SelfReconnectTestSession>(ctx, sslCtx.get(), scenariosB, latch)->connect();

    latch.wait();

    CHECK(scenariosA.empty());
    CHECK(scenariosB.empty());

    wg.reset();
}
