// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <doctest/doctest.h>
#include "TestSslCtx.hpp"

#include <fishnets/Context.hpp>
#include <fishnets/WsServerHandler.hpp>
#include <fishnets/util/WsSessionHandler.hpp>

#include <cstring>
#include <deque>
#include <optional>
#include <thread>

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

    bool operator==(itlib::span<const uint8_t> bin) const {
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

class TestClientSession final : public fishnets::WsSessionHandler {
    void sendNext() {
        auto& packet = packets[sendIndex++];
        if (packet.istext) wsSend(packet.text);
        else wsSend(packet.binary);
    }

    void closeIfDone() {
        if (sendIndex == packets.size() && receivedIndex == packets.size()) {
            wsClose();
        }
    }

    void wsOpened(std::string_view target) override {
        auto ep = wsGetEndpointInfo();
        CHECK(ep.address == "127.0.0.1");
        CHECK(ep.port == Test_Port);
        CHECK(target == SessionTargetFixture::target);

        sendNext();
        wsReceive();
    }

    void wsReceivedBinary(itlib::span<uint8_t> binary, bool complete) override {
        REQUIRE(receivedIndex < packets.size());
        CHECK(complete);
        CHECK((packets[receivedIndex] == binary));
        ++receivedIndex;
        closeIfDone();
        wsReceive();
    }

    void wsReceivedText(itlib::span<char> text, bool complete) override {
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

public:
    size_t sendIndex = 0;
    size_t receivedIndex = 0;
};

class TestServerSession final : public fishnets::WsSessionHandler {
    void wsOpened(std::string_view target) override {
        auto ep = wsGetEndpointInfo();
        CHECK(ep.address == "127.0.0.1");
        CHECK(target == SessionTargetFixture::target);
        wsReceive();
    }

    void wsReceivedBinary(itlib::span<uint8_t> binary, bool complete) override {
        CHECK(complete);
        REQUIRE(receivedIndex < packets.size());
        CHECK((packets[receivedIndex] == binary));
        sendQueue.push_back(receivedIndex);
        ++receivedIndex;
        send();
        wsReceive();
    }

    void wsReceivedText(itlib::span<char> text, bool complete) override {
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
        else wsSend(packet.binary);
    }

    void wsCompletedSend() override {
        curSend.reset();
        send();
    }

    std::deque<size_t> sendQueue;
    std::optional<size_t> curSend;
    size_t receivedIndex = 0;
};

struct TestServer {
    fishnets::Context m_ctx;
    std::shared_ptr<fishnets::SslContext> m_sslCtx = createServerTestSslCtx();
    std::thread m_thread;

    TestServer() {
        m_ctx.wsServeLocalhost(
            Test_Port,
            std::make_shared<fishnets::SimpleServerHandler>([](const fishnets::EndpointInfo& info) {
                CHECK(info.address == "127.0.0.1");
                return std::make_shared<TestServerSession>();
            }),
            m_sslCtx.get()
        );
        m_thread = std::thread([this] {
            m_ctx.run();
        });
    }
    ~TestServer() {
        m_ctx.stop();
        m_thread.join();
    }
};

std::shared_ptr<TestClientSession> runTestClient() {
    auto ret = std::make_shared<TestClientSession>();
    fishnets::Context ctx;
    auto sslCtx = createClientTestSslCtx();
    ctx.wsConnect(
        ret,
        {"127.0.0.1", Test_Port},
        SessionTargetFixture::target,
        sslCtx.get()
    );
    ctx.run();
    return ret;
};

TEST_CASE("connect") {
    TestServer server;
    auto s = runTestClient();
    REQUIRE(s);
    CHECK(s->sendIndex == packets.size());
    CHECK(s->receivedIndex == packets.size());
}

TEST_CASE("connect target") {
    SessionTargetFixture f("/xyz");

    TestServer server;
    auto s = runTestClient();
    REQUIRE(s);
    CHECK(s->sendIndex == packets.size());
    CHECK(s->receivedIndex == packets.size());
}
