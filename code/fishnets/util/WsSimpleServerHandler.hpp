// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "../WsServerHandler.hpp"
#include <itlib/ufunction.hpp>

namespace fishnets {

class FISHNETS_API WsSimpleServerHandler : public WsServerHandler {
public:
    using AcceptFunc = itlib::ufunction<void(WsServerConnectionPtr)>;
    AcceptFunc accept;

    explicit WsSimpleServerHandler(AcceptFunc f) : accept(std::move(f)) {}
    ~WsSimpleServerHandler();

    virtual void onAccept(WsServerConnectionPtr connection) final override {
        accept(std::move(connection));
    }
};

} // namespace fishnets
