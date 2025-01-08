// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketClientSSLSettings.hpp>
#include <fishnets/WebSocketSession.hpp>

#include <iostream>

class OneshotSession final : public fishnets::WebSocketSession
{
    itlib::span<uint8_t> wsOpened() override
    {
        std::cout << "Connected\n";
        m_sent = "cool message";
        wsSend(m_sent);
        return {};
    }

    void wsClosed() override
    {
        std::cout << "Disconnected\n";
    }

    itlib::span<uint8_t> wsReceivedBinary(itlib::span<uint8_t> binary, bool) override
    {
        std::cout << "Received binary with size " << binary.size() << '\n';
        wsClose();
        return {};
    }

    itlib::span<uint8_t> wsReceivedText(itlib::span<char> text, bool) override
    {
        std::string_view str(text.data(), text.size());
        std::cout << "Received text " << str << '\n';
        wsClose();
        return {};
    }

    std::string m_sent;
};

#include "RootCertificates.inl"

int main()
{
    // fishnets::WebSocketClientSSLSettings sslSettings;
    // sslSettings.customCertificates = rootCertificates;
    // fishnets::WebSocketClient client(std::make_shared<OneshotSession>(), "echo.websocket.org", 443, &sslSettings);
    // fishnets::WebSocketClient client(std::make_shared<OneshotSession>(), "echo.websocket.org", 80);
    fishnets::WebSocketClient client(
        [](const fishnets::WebSocketEndpointInfo&) { return std::make_shared<OneshotSession>(); });
    client.connect("localhost", 7654);

    return 0;
}
