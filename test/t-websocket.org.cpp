// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <xeq/context.hpp>
#include <fishnets/SslContext.hpp>
#include <fishnets/util/WsSessionHandler.hpp>
#include <fishnets/WsConnect.hpp>
#include <fishnets/WsConnectionHandler.hpp>

#include <doctest/doctest.h>

#include <deque>
#include <optional>

struct Packet {
    std::string str;
    std::vector<uint8_t> blob;
    bool text() const { return blob.empty(); }
    bool binary() const { return !text(); }
};

const std::vector<Packet> Test_Packets = {
    Packet{"hello", {}},
    Packet{"world", {}},
    Packet{"", {1, 2, 3}},
    Packet{"", {5, 6, 7}},
    Packet{"buenos dias", {}},
    Packet{"", {35, 46, 57}},
};


class EchoSession final : public fishnets::WsConnectionHandler, public fishnets::WsSessionHandler {
public:
    std::optional<std::deque<Packet>> packets;

    void onConnected(fishnets::WebSocketPtr ws, std::string_view target) override {
        wsAttach(std::move(ws));
        wsReceive();
    }

    void trySendNext() {
        if (packets->empty()) {
            wsClose();
        }
        else {
            auto& packet = packets->front();
            if (packet.text()) {
                wsSend(packet.str);
            }
            else {
                wsSend(as_bytes(std::span(packet.blob)));
            }
        }
    }

    void wsReceivedBinary(std::span<std::byte> binary, bool complete) override {
        CHECK(complete);
        auto& packet = packets->front();
        CHECK(packet.binary());
        std::span expected(packet.blob);
        CHECK(std::equal(binary.begin(), binary.end(), expected.begin(), expected.end(),
            [](std::byte b, uint8_t e) { return b == std::byte(e); }
        ));
        packets->pop_front();
        trySendNext();
    }

    void wsReceivedText(std::span<char> text, bool complete) override {
        CHECK(complete);
        std::string_view sv(text.data(), text.size());
        if (!packets) {
            // we received the greeting from websocket.org
            CHECK(sv.starts_with("Request served by "));
            packets.emplace(Test_Packets.begin(), Test_Packets.end());
        }
        else {
            auto& packet = packets->front();
            CHECK(packet.text());
            CHECK(packet.str == sv);
            packets->pop_front();
        }

        trySendNext();
    }

    void wsCompletedSend() override {
        wsReceive();
    }
};

TEST_CASE("websocket.org echo async") {
    xeq::context ctx;
    fishnets::SslContext sslCtx;

    auto session = std::make_shared<EchoSession>();
    wsConnect(ctx, session, "wss://echo.websocket.org", &sslCtx);
    ctx.run();
    REQUIRE(session->packets);
    CHECK(session->packets->empty());
}
