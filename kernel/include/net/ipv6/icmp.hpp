// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6/wire.hpp"

namespace ax::ip6 {
struct ErrorQuote {
    Address source, destination;
    const uint8_t* transport = nullptr;
    uint32_t information = 0;
    uint8_t protocol = 0, type = 0, code = 0;
    int error = 0;
    bool hard = false;
};

// Accepts a truncated quote only when its full extension chain and the first
// eight transport bytes are present. The caller owns outer checksum checks.
bool error_quote(const uint8_t*, size_t, ErrorQuote&);
} // namespace ax::ip6
