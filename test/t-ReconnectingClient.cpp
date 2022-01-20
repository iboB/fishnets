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

TEST_SUITE_BEGIN("fishnets");

class TestClientSession final : public fishnets::WebSocketSession
{
    void wsOpened() override {}
    void wsClosed() override {}
    void wsReceivedBinary(itlib::memory_view<uint8_t>) override {}
    void wsReceivedText(itlib::memory_view<char>) override {}
    void wsCompletedSend() override {}
};

TEST_CASE("failing client")
{

}

