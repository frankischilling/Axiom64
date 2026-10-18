// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::ip4 {
constexpr unsigned reassembly_capacity = 32;
constexpr uint64_t reassembly_lifetime = 6000; // 60 seconds in the kernel's 100 Hz clock.

enum class FragmentStatus : uint8_t { whole, pending, duplicate, complete, rejected, exhausted };

struct Reassembled {
    FragmentStatus status = FragmentStatus::rejected;
    // Only complete returns allocated bytes. The caller owns them and calls ax::release.
    uint8_t* bytes = nullptr;
    size_t length = 0;
    bool link_broadcast = false;
};

// The callback borrows the original first fragment's header and eight payload bytes.
// Expired state is detached before the callback. Missing first fragments produce no callback.
using FragmentExpired = void (*)(unsigned index, const uint8_t*, size_t, bool link_broadcast);

// Callers establish local destination/source policy before admission. This module
// checks IP header bounds/checksum, fragment geometry and tuple ownership, and copies
// accepted bytes before returning. Unfragmented input never changes a fragment
// queue merely because its identification field happens to match.
Reassembled reassemble(unsigned index, const uint8_t*, size_t, uint64_t now,
                       bool link_broadcast = false, FragmentExpired = nullptr);

void reassembly_expire(uint64_t now, FragmentExpired = nullptr);

// Address zero discards every queue; other addresses release only that destination.
// Addresses are host-order IPv4 values, like the rest of the IPv4 interface.
void reassembly_discard(uint32_t destination = 0);
} // namespace ax::ip4
