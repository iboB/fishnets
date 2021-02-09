// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketClientSSLSettings.hpp>
#include <fishnets/WebSocketSession.hpp>

#include <iostream>

class OneshotSession final : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
        std::cout << "Connected\n";
        m_sent = "cool message";
        wsSend(m_sent);
    }

    void wsClosed() override
    {
        std::cout << "Disconnected\n";
    }

    void wsReceivedBinary(itlib::memory_view<uint8_t> binary) override
    {
        std::cout << "Received binary with size " << binary.size() << '\n';
        wsClose();
    }

    void wsReceivedText(itlib::memory_view<char> text) override
    {
        std::string_view str(text.data(), text.size());
        std::cout << "Received text " << str << '\n';
        wsClose();
    }

    void wsCompletedSend() override {}

    std::string m_sent;
};

#include "RootCertificates.inl"

int main()
{
    // fishnets::WebSocketClientSSLSettings sslSettings;
    // sslSettings.customCertificates = rootCertificates;
    // fishnets::WebSocketClient client(std::make_shared<OneshotSession>(), "echo.websocket.org", 443, &sslSettings);
    // fishnets::WebSocketClient client(std::make_shared<OneshotSession>(), "echo.websocket.org", 80);
    fishnets::WebSocketClient client(std::make_shared<OneshotSession>(), "localhost", 7654);

    return 0;
}
