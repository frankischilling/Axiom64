// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/config/routing.hpp"

namespace ax::net::detail {
// Original main-table records retain attributes across address replacement.
// The enclosing ownership journal bounds the complete persisted intent.
struct RouteSnapshot {
    size_t size = 0;
    uint8_t bytes[4096]{};
};

int decode_route(const void*, size_t, Route&, uint32_t* preferred_source = nullptr);
} // namespace ax::net::detail
