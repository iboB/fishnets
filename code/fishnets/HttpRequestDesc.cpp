// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#include "HttpRequestDesc.hpp"
#include <furi/furi.hpp>
#include <stdexcept>

namespace fishnets {

namespace {
std::string portToStr(uint16_t port) {
    if (port == 0) return {};
    return ":" + std::to_string(port);
}
HttpRequestDesc::Scheme schemeFromStr(std::string_view s) {
    if (s == "http") return HttpRequestDesc::HTTP;
    if (s == "https") return HttpRequestDesc::HTTPS;
    return HttpRequestDesc::Unknown_Scheme;
}

void setFromMethodUrl(HttpRequestDesc& desc, std::string method, std::string_view url) {
    auto split = furi::uri_split::from_uri(url);
    desc.method = method;
    desc.scheme = schemeFromStr(split.scheme);
    desc.host = std::string(split.authority);
    desc.target = std::string(split.req_path);
}
} // namespace

HttpRequestDesc::HttpRequestDesc(
    std::string method,
    Scheme scheme,
    std::string host,
    std::string target,
    HeaderFields fields
)
    : method(std::move(method))
    , scheme(scheme)
    , host(std::move(host))
    , target(std::move(target))
    , fields(std::move(fields))
{}

HttpRequestDesc::HttpRequestDesc(
    std::string method,
    Scheme scheme,
    std::string host,
    uint16_t port,
    std::string target,
    HeaderFields fields
) : HttpRequestDesc(
        method,
        scheme,
        std::move(host) + portToStr(port),
        std::move(target),
        std::move(fields)
    )
{}

HttpRequestDesc::HttpRequestDesc(std::string method, std::string_view url, HeaderFields fields)
    : fields(std::move(fields))
{
    setFromMethodUrl(*this, method, url);
}

HttpRequestDesc::HttpRequestDesc(std::string_view request, HeaderFields fields)
    : fields(std::move(fields))
{
    auto space = request.find(' ');
    if (space == std::string_view::npos) {
        throw std::invalid_argument("invalid request string, no spaces");
    }
    auto m = std::string(request.substr(0, space));
    auto u = request.substr(space + 1);
    setFromMethodUrl(*this, m, u);
}


} // namespace fishnets
