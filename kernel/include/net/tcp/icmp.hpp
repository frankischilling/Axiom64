// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::tcp {
// An owned description of the minimum ICMP quote. No packet storage is retained.
struct IcmpError {
    uint32_t local = 0, peer = 0, sequence = 0;
    uint16_t source = 0, destination = 0;
    int error = 0;
    bool abort_request = false;
};

bool decode_icmp_error(const uint8_t*, size_t, IcmpError&);
} // namespace ax::tcp
