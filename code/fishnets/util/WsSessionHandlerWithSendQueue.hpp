// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "WsSessionHandler.hpp"
#include <itlib/pod_vector.hpp>
#include <variant>
#include <string>
#include <optional>
#include <queue>

namespace fishnets {

class FISHNETS_API WsSessionHandlerWithSendQueue : public WsSessionHandler {
protected:
    void wsAddToSendQueue(std::string text);

    using BinaryBufferType = itlib::pod_vector<std::byte>;
    void wsAddToSendQueue(BinaryBufferType binary);
private:
    using WsSessionHandler::wsSend;
    virtual void wsCompletedSend() final override;

    using Item = std::variant<
        std::string, // text
        BinaryBufferType  // binary
    >;

    std::queue<Item> m_queue;
    std::optional<Item> m_curItem;

    void doAddToQueue(Item item);
    void sendCurItem();
};

} // namespace fishnets
