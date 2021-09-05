// fishnets
// Copyright (c) 2021 Borislav Stanimirov
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
#include <fishnets/WebSocketEndpointInfo.hpp>

#include <cstring>
#include <deque>
#include <optional>

constexpr uint16_t Test_Port = 7654;

struct Packet
{
    bool istext = false;
    std::string text;
    std::vector<uint8_t> binary;

    bool operator==(std::string_view str) const
    {
        if (!istext) return false;
        return text == str;
    }

    bool operator==(itlib::const_memory_view<uint8_t> bin) const
    {
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

class TestClientSession final : public fishnets::WebSocketSession
{
    void sendNext()
    {
        auto& packet = packets[sendIndex++];
        if (packet.istext) wsSend(packet.text);
        else wsSend(itlib::make_memory_view(packet.binary));
    }

    void closeIfDone()
    {
        if (sendIndex == packets.size() && receivedIndex == packets.size())
        {
            wsClose();
        }
    }

    void wsOpened() override
    {
        auto ep = wsGetEndpointInfo();
        CHECK(ep.address == "127.0.0.1");
        CHECK(ep.port == Test_Port);

        sendNext();
    }

    void wsClosed() override
    {
    }

    void wsReceivedBinary(itlib::memory_view<uint8_t> binary) override
    {
        REQUIRE(receivedIndex < packets.size());
        CHECK(packets[receivedIndex] == binary);
        ++receivedIndex;
        closeIfDone();
    }

    void wsReceivedText(itlib::memory_view<char> text) override
    {
        REQUIRE(receivedIndex < packets.size());
        std::string_view str(text.data(), text.size());
        CHECK(packets[receivedIndex] == str);
        ++receivedIndex;
        closeIfDone();
    }

    void wsCompletedSend() override
    {
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

class TestServerSession final : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
        auto ep = wsGetEndpointInfo();
        CHECK(ep.address == "127.0.0.1");
    }

    void wsClosed() override
    {
    }

    void wsReceivedBinary(itlib::memory_view<uint8_t> binary) override
    {
        REQUIRE(receivedIndex < packets.size());
        CHECK(packets[receivedIndex] == binary);
        sendQueue.push_back(receivedIndex);
        ++receivedIndex;
        send();
    }

    void wsReceivedText(itlib::memory_view<char> text) override
    {
        REQUIRE(receivedIndex < packets.size());
        std::string_view str(text.data(), text.size());
        CHECK(packets[receivedIndex] == str);
        sendQueue.push_back(receivedIndex);
        ++receivedIndex;
        send();
    }

    void send()
    {
        if (curSend) return;
        if (sendQueue.empty()) return;
        curSend.emplace(sendQueue.front());
        sendQueue.pop_front();
        auto& packet = packets[*curSend];
        if (packet.istext) wsSend(packet.text);
        else wsSend(itlib::make_memory_view(packet.binary));
    }

    void wsCompletedSend() override
    {
        curSend.reset();
        send();
    }

    std::deque<size_t> sendQueue;
    std::optional<size_t> curSend;
    size_t receivedIndex = 0;
};

fishnets::WebSocketSessionPtr Make_ServerSession(const fishnets::WebSocketEndpointInfo& info)
{
    CHECK(info.address == "127.0.0.1");
    return std::make_shared<TestServerSession>();
}

TEST_CASE("basic")
{
    fishnets::WebSocketServer server(Make_ServerSession, Test_Port, 1, testServerSSLSettings.get());

    auto clientSession = std::make_shared<TestClientSession>();
    fishnets::WebSocketClient client(clientSession, "localhost", Test_Port, testClientSSLSettings.get());
    CHECK(clientSession->sendIndex == packets.size());
    CHECK(clientSession->receivedIndex == packets.size());
}

fishnets::WebSocketSessionPtr Deny_ServerSession(const fishnets::WebSocketEndpointInfo& info)
{
    CHECK(info.address == "127.0.0.1");
    return {};
}

TEST_CASE("server decline")
{
    fishnets::WebSocketServer server(Deny_ServerSession, Test_Port, 1, testServerSSLSettings.get());

    auto clientSession = std::make_shared<TestClientSession>();
    fishnets::WebSocketClient client(clientSession, "localhost", Test_Port, testClientSSLSettings.get());
    CHECK(clientSession->sendIndex == 0);
    CHECK(clientSession->receivedIndex == 0);
}
