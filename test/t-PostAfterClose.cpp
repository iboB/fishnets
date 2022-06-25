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

#include <atomic>

TEST_SUITE_BEGIN("fishnets");

class TestClientSession final : public fishnets::WebSocketSession
{
    void wsReceivedBinary(itlib::span<uint8_t>) override
    {
        ++receivedPackages;
    }

    void wsReceivedText(itlib::span<char>) override
    {
        ++receivedPackages;
    }

public:
    int receivedPackages = 0;
};

std::atomic_bool postAfterCloseDone = false;
std::atomic_bool serverSessionDestroyed = false;

class TestServerSession final : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
        opened = true;
        postWSIOTask([this]() { wsClose(); });
    }

    void wsClosed() override
    {
        closed = true;
    }

public:
    ~TestServerSession()
    {
        serverSessionDestroyed = true; // destoyed, so not leaked
    }

    void postAfterClose()
    {
        postWSIOTask([this]() {
            wsSend("foo"); // should safely fail (but also touch "this")
            opened = true; // definitely touch "this"
            postAfterCloseDone = true;
        });
    }

    bool opened = false;
    std::atomic_bool closed = false;
};

constexpr uint16_t Test_Port = 7654;

std::shared_ptr<TestServerSession> serverSession;
fishnets::WebSocketSessionPtr Make_ServerSession(const fishnets::WebSocketEndpointInfo&)
{
    REQUIRE(!serverSession);
    serverSession = std::make_shared<TestServerSession>();
    return serverSession;
}

std::shared_ptr<TestClientSession> clientSession;
fishnets::WebSocketSessionPtr Make_ClientSession(const fishnets::WebSocketEndpointInfo&)
{
    REQUIRE(!clientSession);
    clientSession = std::make_shared<TestClientSession>();
    return clientSession;
}

TEST_CASE("post after close")
{
    fishnets::WebSocketServer server(Make_ServerSession, Test_Port, 1, testServerSSLSettings.get());

    {
        fishnets::WebSocketClient client(Make_ClientSession, testClientSSLSettings.get());
        client.connect("localhost", Test_Port);
        CHECK(clientSession->receivedPackages == 0);
        CHECK(clientSession.use_count() == 1);
        clientSession.reset();
    }

    REQUIRE(serverSession);
    CHECK(serverSession->opened);
    while (!serverSession->closed); // silly spinlock
    serverSession->postAfterClose();
    serverSession.reset();

    // more silly spinlocks
    while (!postAfterCloseDone);
    while (!serverSessionDestroyed);
}
