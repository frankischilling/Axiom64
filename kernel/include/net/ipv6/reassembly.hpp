// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6/wire.hpp"

namespace ax::ip6 {
constexpr unsigned reassembly_capacity = 32;
constexpr uint64_t reassembly_lifetime = 6000; // 60 seconds at 100 Hz.

enum class FragmentStatus : uint8_t {
    whole,
    pending,
    duplicate,
    complete,
    rejected,
    exhausted,
    parameter_problem
};

struct Reassembled {
    FragmentStatus status = FragmentStatus::rejected;
    // Complete transfers an allocated IPv6 packet without its Fragment header.
    // The caller releases it and retains the fact that it was fragmented.
    uint8_t* bytes = nullptr;
    size_t length = 0;
    uint32_t error_pointer = 0;
    uint8_t error_code = 0;
};

// Borrows up to 1232 original bytes from the offset-zero fragment. The queue is
// detached before notification; queues without that fragment produce no notice.
using FragmentExpired = void (*)(unsigned index, const uint8_t*, size_t);

// The caller validates local destination and link/source ownership first.
// Admission copies bytes; atomic/whole packets never join matching queues.
Reassembled reassemble(unsigned index, const uint8_t*, size_t, uint64_t now,
                       FragmentExpired = nullptr);
void reassembly_expire(uint64_t now, FragmentExpired = nullptr);

// No destination clears everything. A scoped destination also selects its link.
void reassembly_discard(const Address* destination = nullptr, unsigned index = 0);
} // namespace ax::ip6
