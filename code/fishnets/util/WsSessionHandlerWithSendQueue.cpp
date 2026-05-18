#include "WsSessionHandlerWithSendQueue.hpp"

namespace fishnets {

void WsSessionHandlerWithSendQueue::wsAddToSendQueue(std::string text) {
    doAddToQueue(std::move(text));
}

void WsSessionHandlerWithSendQueue::wsAddToSendQueue(BinaryBufferType binary) {
    doAddToQueue(std::move(binary));
}

void WsSessionHandlerWithSendQueue::doAddToQueue(Item item) {
    if (!m_curItem) {
        m_curItem = std::move(item);
        sendCurItem();
    }
    else {
        m_queue.push(std::move(item));
    }
}

void WsSessionHandlerWithSendQueue::wsCompletedSend() {
    m_curItem.reset();

    if (m_queue.empty()) return;

    m_curItem = std::move(m_queue.front());
    m_queue.pop();
    sendCurItem();
}

namespace {
std::string_view makeView(const std::string& str) { return str; }
std::span<const std::byte> makeView(const itlib::pod_vector<std::byte>& vec) { return vec; }
}

void WsSessionHandlerWithSendQueue::sendCurItem() {
    std::visit([&](auto& item) { wsSend(makeView(item)); }, *m_curItem);
}

} // namespace fishnets
