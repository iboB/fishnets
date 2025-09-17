// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/Context.hpp>
#include <fishnets/SslContext.hpp>
#include <fishnets/WsConnect.hpp>
#include <fishnets/util/WsSessionHandler.hpp>

#include <iostream>

// session which sends a single frame, receives a single frame and then closes the connection
class OneshotSession final : public fishnets::WsSessionHandler {
    void wsOpened(std::string_view target) override {
        auto ep = wsGetEndpointInfo();
        std::cout << "Connected to: " << ep.address << ':' << ep.port << target << '\n';
        m_msg = "cool message";
        wsSend(m_msg);
    }

    void wsCompletedSend() override {
        wsReceive();
    }

    void wsReceivedBinary(std::span<uint8_t> binary, bool) override {
        std::cout << "Received binary with size " << binary.size() << '\n';
        wsClose();
    }

    void wsReceivedText(std::span<char> text, bool) override {
        std::string_view str(text.data(), text.size());
        std::cout << "Received text: " << str << '\n';
        wsClose();
    }

    std::string m_msg;
};

#include "RootCertificates.inl"

int main() {
    fishnets::Context ctx;
    //fishnets::SslContext ssl;

    wsConnect(
        ctx,
        std::make_shared<OneshotSession>(),
        //"wss://echo.websocket.org",
        "ws://localhost:7654"
    );

    ctx.run();

    return 0;
}
