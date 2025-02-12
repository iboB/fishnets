// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/Context.hpp>
#include <fishnets/SslContext.hpp>
#include <fishnets/util/WsSessionHandler.hpp>

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


class EchoSession : public fishnets::WsSessionHandler {
public:
    std::optional<std::deque<Packet>> packets;

    void wsOpened(std::string_view) override {
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
                wsSend(packet.blob);
            }
        }
    }

    void wsReceivedBinary(itlib::span<uint8_t> binary, bool complete) {
        CHECK(complete);
        auto& packet = packets->front();
        CHECK(packet.binary());
        itlib::span expected(packet.blob);
        CHECK(std::equal(binary.begin(), binary.end(), expected.begin(), expected.end()));
        packets->pop_front();
        trySendNext();
    }

    void wsReceivedText(itlib::span<char> text, bool complete) {
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
    fishnets::Context ctx;
    fishnets::SslContext sslCtx;

    auto session = std::make_shared<EchoSession>();
    ctx.wsConnect(session, "wss://echo.websocket.org", &sslCtx);
    ctx.run();
}
