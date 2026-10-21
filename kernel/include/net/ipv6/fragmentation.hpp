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

// Encode one piece of an owned, fixed-header source datagram. Offset counts
// payload bytes accepted by the device; a nonzero offset keeps fragmentation
// active even if the MTU grows. Every piece retains the same identification.
// Input and output must not overlap. Errors leave output unchanged. Extension
// chains belong to their source encoder and are not accepted by this interface.
FragmentPiece fragment_packet(const uint8_t*, size_t available, uint32_t mtu, size_t offset,
                              uint32_t identification, uint8_t* output, size_t capacity);
} // namespace ax::ip6
