// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::ip6 {
struct FragmentPiece {
    int error = -22;
    size_t length = 0, consumed = 0;
    bool complete = false;
};

enum class FragmentLayout { protocol, linux_socket };

// Encode one piece of an owned source datagram. Offset counts fragmentable
// bytes accepted by the device; a nonzero offset keeps fragmentation active even
// if the MTU grows. Hop-by-Hop headers and headers through the last Routing header
// repeat before every Fragment header. Later Destination headers are fragmented.
// The first fragment retains the complete extension and upper-layer header chain.
// Every piece retains the same identification. Input and output must not overlap.
// Errors leave output unchanged; existing Fragment, AH and ESP inputs are opaque.
// Linux socket output also repeats Destination options when no Routing header
// exists, matching the observed native datagram layout.
FragmentPiece fragment_packet(const uint8_t*, size_t available, uint32_t mtu, size_t offset,
                              uint32_t identification, uint8_t* output, size_t capacity,
                              FragmentLayout = FragmentLayout::protocol);
} // namespace ax::ip6
