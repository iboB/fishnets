// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include <fishnets/HttpRequestDesc.hpp>
#include <doctest/doctest.h>

using fishnets::HttpRequestDesc;

TEST_CASE("HttpRequestDesc") {
    HttpRequestDesc h0("GET", HttpRequestDesc::HTTP, "example.com", 219, "/path", {.userAgent = "code"});
    CHECK(h0.method == "GET");
    CHECK(h0.scheme == HttpRequestDesc::HTTP);
    CHECK(h0.host == "example.com:219");
    CHECK(h0.target == "/path");
    CHECK(h0.fields.userAgent == "code");
    CHECK(h0.fields.contentType.empty());
    CHECK_FALSE(h0.fields.keepAlive);

    HttpRequestDesc h1("POST", "https://foo.com:3119/content", {.contentType = "text"});
    CHECK(h1.method == "POST");
    CHECK(h1.scheme == HttpRequestDesc::HTTPS);
    CHECK(h1.host == "foo.com:3119");
    CHECK(h1.target == "/content");
    CHECK(h1.fields.userAgent.empty());
    CHECK(h1.fields.contentType == "text");
    CHECK_FALSE(h1.fields.keepAlive);

    HttpRequestDesc h2("PUT http://bar.org/data", {.keepAlive = true});
    CHECK(h2.method == "PUT");
    CHECK(h2.scheme == HttpRequestDesc::HTTP);
    CHECK(h2.host == "bar.org");
    CHECK(h2.target == "/data");
    CHECK(h2.fields.userAgent.empty());
    CHECK(h2.fields.contentType.empty());
    CHECK(h2.fields.keepAlive);
}
