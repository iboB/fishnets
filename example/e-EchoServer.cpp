// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/WebSocketServer.hpp>
#include <fishnets/WebSocketSession.hpp>
#include <fishnets/WebSocketEndpointInfo.hpp>
#include <fishnets/WebSocketServerSSLSettings.hpp>

#include <iostream>
#include <thread>

class EchoServerSession final : public fishnets::WebSocketSession
{
    void wsOpened() override
    {
        std::cout << "New session " << this << '\n';
        auto endpoint = wsGetEndpointInfo();
        std::cout << endpoint.address << " : " << endpoint.port << '\n';
    }

    void wsClosed() override
    {
        std::cout << "Closed session " << this << '\n';
    }

    void wsReceivedBinary(itlib::span<uint8_t> binary) override
    {
        std::cout << "Received binary with size " << binary.size() << '\n';
        std::cout << "Ignoring\n";
    }

    void wsReceivedText(itlib::span<char> text) override
    {
        std::string_view str(text.data(), text.size());
        std::cout << "Received text " << str << '\n';
        if (m_sent.empty())
        {
            std::cout << "Sending back\n";
            m_sent = str;
            wsSend(m_sent);
        }
        else
        {
            std::cout << "Previous send is not complete. Ignoring\n";
        }
    }

    void wsCompletedSend() override
    {
        std::cout << "Completed send. Ready for more\n";
        m_sent.clear();
    }

    std::string m_sent;
};

fishnets::WebSocketSessionPtr makeSession(const fishnets::WebSocketEndpointInfo&)
{
    return std::make_shared<EchoServerSession>();
}

#include "ServerCertificate.inl"

int main()
{
    fishnets::WebSocketServerSSLSettings* psslSettings = nullptr;

    // fishnets::WebSocketServerSSLSettings sslSettings;
    // sslSettings.certificate = certificate;
    // sslSettings.privateKey = privateKey;
    // sslSettings.tmpDH = tmpDH;
    // psslSettings = &sslSettings;

    fishnets::WebSocketServer server(makeSession, 7654, 3, psslSettings);
    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}
