// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once
#include <variant>
#include <span>

namespace fishnets {

class HttpRequestBody {
public:
    const std::span<const uint8_t>& data() const { return m_data; }

private:
    std::span<const uint8_t> m_data;

    std::variant<
        std::monostate,
        std::vector<uint8_t>, // copied data from the outside
        std::unique_ptr<void, void(*)(void*)> // custom data from the outside
    > m_ownedData;
};

} // namespace fishnets
