// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::ip4 {
struct FragmentPiece {
    int error = -22;
    size_t length = 0, consumed = 0;
    bool complete = false;
};

// Copy the next MTU-bounded IP packet into caller-owned storage. Offset counts
// payload bytes already submitted from this input packet, and must be aligned
// to eight bytes. Advance it only after the driver accepts the returned piece.
// Source and destination storage must not overlap. Input is never modified;
// errors leave output untouched. DF forbids splitting. Existing fragment offsets
// and MF survive re-fragmentation; only copied options survive in later pieces.
FragmentPiece fragment_packet(const uint8_t*, size_t available, size_t mtu, size_t offset,
                              uint8_t* output, size_t capacity);
} // namespace ax::ip4
