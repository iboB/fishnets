// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "TestSslCtx.hpp"
#include <fishnets/SslContext.hpp>

std::shared_ptr<fishnets::SslContext> createTestSslCtx() {
    return std::make_shared<fishnets::SslContext>();
}

#include "../example/RootCertificates.inl"
#include "../example/ServerCertificate.inl"

std::shared_ptr<fishnets::SslContext> createClientTestSslCtx() {
    auto ctx = createTestSslCtx();
    for (auto& cert : rootCertificates) {
        ctx->addCertificateAuthority(cert);
    }
    return ctx;
}

std::shared_ptr<fishnets::SslContext> createServerTestSslCtx() {
    auto ctx = createTestSslCtx();
    ctx->useCertificateChain(certificate);
    ctx->usePrivateKey(privateKey);
    ctx->useTmpDh(tmpDh);
    return ctx;
}
