// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "API.h"
#include <memory>
#include <string>

namespace fishnets {

class FISHNETS_API SslContext {
public:
    SslContext();
    ~SslContext();
    SslContext(const SslContext&) = delete;
    SslContext& operator=(const SslContext&) = delete;

    // the functions throw std::exception on error

    // strings or files in pem format

    void useCertificateChain(std::string certificate);
    void useCertificateChainFile(std::string certificateFile);

    void usePrivateKey(std::string privateKey);
    void usePrivateKeyFile(std::string privateKeyFile);

    void useTmpDh(std::string tmpDh);
    void useTmpDhFile(std::string tmpDhFile);

    // return false on error
    void addCertificateAuthority(std::string ca);

    // not supported yet
    // void enableNativeCertificateSupport();

    struct Impl; // opaque implementation
    Impl& impl() { return *m_impl; }
private:
    std::unique_ptr<Impl> m_impl;
};

} // namespace fishnets
