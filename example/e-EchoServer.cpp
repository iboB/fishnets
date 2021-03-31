// fishnets
// Copyright (c) 2021 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
//
#include <fishnets/WebSocketServer.hpp>
#include <fishnets/WebSocketSession.hpp>
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

    void wsReceivedBinary(itlib::memory_view<uint8_t> binary) override
    {
        std::cout << "Received binary with size " << binary.size() << '\n';
        std::cout << "Ignoring\n";
    }

    void wsReceivedText(itlib::memory_view<char> text) override
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

fishnets::WebSocketSessionPtr makeSession()
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
