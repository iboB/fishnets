// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <xeq/context.hpp>
#include <fishnets/Resolve.hpp>
#include <doctest/doctest.h>

template <typename... Args>
fishnets::ResolveResult resolveSync(Args&&... args) {
    xeq::context ctx;
    fishnets::ResolveResult ret = itlib::unexpected("???");
    fishnets::resolve(ctx, std::forward<Args>(args)..., [&ret](fishnets::ResolveResult result) {
        ret = std::move(result);
    });
    ctx.run();
    return ret;
}

TEST_CASE("resolve ip") {
    auto check_success = [](fishnets::ResolveResult res, fishnets::EndpointInfo expected) {
        REQUIRE(res.has_value());
        REQUIRE(res->size() == 1);
        auto& f = res->front();
        CHECK(f.address == expected.address);
        CHECK(f.port == expected.port);
    };

    check_success(resolveSync("8.8.8.8", "1234"), {"8.8.8.8", 1234});
    check_success(resolveSync("1.1.1.1", uint16_t(3)), {"1.1.1.1", 3});
    check_success(resolveSync("http://2.2.2.2:15000"), {"2.2.2.2", 15000});
    check_success(resolveSync("http://1.2.4.5"), {"1.2.4.5", 80});
    check_success(resolveSync("https://1.2.4.5"), {"1.2.4.5", 443});
    check_success(resolveSync("wss://192.168.0.1:25"), {"192.168.0.1", 25});
    check_success(resolveSync("https://[2606:4700:4700::1111]:80"), {"2606:4700:4700::1111", 80});

    auto check_failure = [](fishnets::ResolveResult res, std::string_view error = {}) {
        REQUIRE(res.has_error());
        if (!error.empty()) {
            CHECK(res.error() == error);
        }
    };

    check_failure(resolveSync("foo:1.2.3.4:5"), "unsupported scheme: foo");
    check_failure(resolveSync("300.400.500.600", uint16_t(4)));
}

TEST_CASE("resolve address") {
    CHECK(resolveSync("https://google.com"));
    CHECK(resolveSync("http://yahoo.com"));
    CHECK(resolveSync("yahoo.com", uint16_t(443)));
    CHECK_FALSE(resolveSync("http://no-such-address.nope"));
}
