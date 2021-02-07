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

class CounterClientSession : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
    }

    void wsClosed() override
    {
    }

    void wsReceivedBinary(itlib::const_memory_view<uint8_t> binary) override
    {
    }

    void wsReceivedText(std::string_view text) override
    {
    }

    void wsCompletedSend() override
    {
    }
};

TEST_CASE("basic")
{

}
