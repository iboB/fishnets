// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "HttpRequestHeader.hpp"
#include <furi/furi.hpp>

namespace fishnets {

namespace {
std::string portToStr(uint16_t port) {
    if (port == 0) return {};
    return ":" + std::to_string(port);
}
HttpRequestHeader::Scheme schemeFromStr(std::string_view s) {
    if (s == "http") return HttpRequestHeader::HTTP;
    if (s == "https") return HttpRequestHeader::HTTPS;
    return HttpRequestHeader::Unknown_Scheme;
}
} // namespace

HttpRequestHeader HttpRequestHeader::make(
    Method method,
    Scheme scheme,
    std::string host,
    uint16_t port,
    std::string target,
    HeaderFields fields
) {
    return {
        .method = method,
        .scheme = scheme,
        .host = std::move(host) + portToStr(port),
        .target = std::move(target),
        .fields = std::move(fields)
    };
}

HttpRequestHeader HttpRequestHeader::make(Method method, std::string_view url, HeaderFields fields) {
    auto split = furi::uri_split::from_uri(url);
    return {
        .method = method,
        .scheme = schemeFromStr(split.scheme),
        .host = std::string(split.authority),
        .target = std::string(split.req_path),
        .fields = std::move(fields)
    };
}

} // namespace fishnets
