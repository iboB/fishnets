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

#include <cstring>

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
        sendNext();
    }

    void wsClosed() override
    {
    }

    void wsReceivedBinary(itlib::const_memory_view<uint8_t> binary) override
    {
        REQUIRE(receivedIndex < packets.size());
        CHECK(packets[receivedIndex] == binary);
        ++receivedIndex;
        closeIfDone();
    }

    void wsReceivedText(std::string_view text) override
    {
        REQUIRE(receivedIndex < packets.size());
        CHECK(packets[receivedIndex] == text);
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

    size_t sendIndex = 0;
    size_t receivedIndex = 0;
};

class TestServerSession final : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
    }

    void wsClosed() override
    {
    }

    void wsReceivedBinary(itlib::const_memory_view<uint8_t> binary) override
    {
        REQUIRE(receivedIndex < packets.size());
        CHECK(packets[receivedIndex] == binary);
        wsSend(itlib::make_memory_view(packets[receivedIndex].binary));
        ++receivedIndex;
    }

    void wsReceivedText(std::string_view text) override
    {
        REQUIRE(receivedIndex < packets.size());
        CHECK(packets[receivedIndex] == text);
        wsSend(packets[receivedIndex].text);
        ++receivedIndex;
    }

    void wsCompletedSend() override
    {
    }

    size_t receivedIndex = 0;
};

fishnets::WebSocketSessionPtr Make_ServerSession() { return std::make_shared<TestServerSession>(); }

TEST_CASE("basic")
{
    const uint16_t port = 7654;
    fishnets::WebSocketServer server(Make_ServerSession, port, 1, testServerSSLSettings.get());

    auto clientSession = std::make_shared<TestClientSession>();
    fishnets::WebSocketClient client(clientSession, "localhost", port, testClientSSLSettings.get());
}
