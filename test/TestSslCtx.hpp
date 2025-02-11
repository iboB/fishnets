// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <memory>

namespace fishnets {
class SslContext;
}

std::shared_ptr<fishnets::SslContext> createClientTestSslCtx();
std::shared_ptr<fishnets::SslContext> createServerTestSslCtx();
