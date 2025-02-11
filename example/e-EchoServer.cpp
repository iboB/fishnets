// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/Context.hpp>
#include <fishnets/WsServerHandler.hpp>
#include <fishnets/util/WsSessionHandler.hpp>

#include <iostream>
#include <thread>

class EchoServerSession final : public fishnets::WsSessionHandler {
    void wsOpened(std::string_view target) override {
        auto ep = wsGetEndpointInfo();
        std::cout << "New session from to '" << target << "' from " << ep.address << ':' << ep.port << '\n';
        wsReceive();
    }

    void wsReceivedBinary(itlib::span<uint8_t> binary, bool) override {
        std::cout << "Received binary with size " << binary.size() << '\n';
        std::cout << "Ignoring\n";
        wsReceive();
    }

    void wsReceivedText(itlib::span<char> text, bool) override {
        std::string_view str(text.data(), text.size());
        std::cout << "Received text " << str << '\n';
        if (m_send.empty()) {
            std::cout << "Sending back\n";
            m_send = str;
            wsSend(m_send);
        }
        else {
            std::cout << "Previous send is not complete. Ignoring\n";
        }
        wsReceive();
    }

    void wsCompletedSend() override {
        std::cout << "Completed send. Ready for more\n";
        m_send.clear();
    }

    std::string m_send;
};

#include "ServerCertificate.inl"

int main() {
    fishnets::Context ctx;

    ctx.wsServe(
        {fishnets::IPv4, 7654},
        std::make_shared<fishnets::SimpleServerHandler>([](const fishnets::EndpointInfo&) {
            return std::make_shared<EchoServerSession>();
        })
    );

    ctx.run();
    return 0;
}
