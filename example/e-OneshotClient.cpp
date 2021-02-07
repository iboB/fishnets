#include <fishnets/WebSocketClient.hpp>
#include <fishnets/WebSocketClientSSLSettings.hpp>
#include <fishnets/WebSocketSession.hpp>

#include "RootCertificates.inl"

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

    void wsReceivedBinary(itlib::const_memory_view<uint8_t> binary) override
    {
        std::cout << "Received binary with size " << binary.size() << '\n';
        wsClose();
    }

    void wsReceivedText(std::string_view text) override
    {
        std::cout << "Received text " << text << '\n';
        wsClose();
    }

    void wsCompletedSend() override {}

    std::string m_sent;
};

int main()
{
    // fishnets::WebSocketClientSSLSettings sslSettings;
    // sslSettings.customCertificates = rootCertificates;
    // fishnets::WebSocketClient client(std::make_shared<OneshotSession>(), "echo.websocket.org", 443, &sslSettings);
    fishnets::WebSocketClient client(std::make_shared<OneshotSession>(), "localhost", 7654);

    return 0;
}
