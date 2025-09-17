// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include "util/byte_span.hpp"
#include <variant>
#include <vector>
#include <span>

namespace fishnets {

class HttpRequestBody {
public:
    template <typename T>
    explicit HttpRequestBody(std::span<const T> data) {
        auto bspan = as_byte_span(data);
        std::vector<uint8_t> vec(bspan.begin(), bspan.end());
        m_data = vec;
        m_ownedData = std::move(vec);
    }

    // intentionally implicit
    HttpRequestBody(std::string body) {
        m_ownedData = std::move(body);
        auto& str = std::get<std::string>(m_ownedData);
        m_data = as_byte_span(std::span(str));
    }

    template <typename T>
    static HttpRequestBody copy(const T& data) {
        return HttpRequestBody(data);
    }

    template <typename T>
    static HttpRequestBody ref(std::span<const T> data) {
        HttpRequestBody ret;
        ret.m_data = as_byte_span(data);
        return ret;
    }
    static HttpRequestBody ref(std::string_view body) {
        HttpRequestBody ret;
        ret.m_data = as_byte_span(std::span(body.data(), body.size()));
        return ret;
    }

    static HttpRequestBody take(std::string& body) {
        return HttpRequestBody(std::move(body));
    }
    template <typename Container>
    static HttpRequestBody take(Container&& data) {
        HttpRequestBody ret;
        auto ptr = std::make_unique<Container, void(*)(void*)>(
            new Container(std::forward<Container>(data)),
            +[](void* p) { delete static_cast<Container*>(p); }
        );
        ret.m_data = as_byte_span(std::span(*ptr));
        ret.m_ownedData = std::move(ptr);
    }


    const std::span<const uint8_t>& data() const { return m_data; }

private:
    HttpRequestBody() = default;

    std::span<const uint8_t> m_data;

    std::variant<
        std::monostate,
        std::string, // copied or moved string from the outside
        std::vector<uint8_t>, // copied or moved vector uint8_t data from the outside
        std::unique_ptr<void, void(*)(void*)> // custom moved container from the outside
    > m_ownedData;
};

} // namespace fishnets
