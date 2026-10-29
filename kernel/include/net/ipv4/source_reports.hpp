// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4/source_aggregate.hpp"
#include <cstdint>

namespace ax::ip4 {
// Pending records belong to the interface aggregate. Current source slots stay
// reserved even after their counters reach zero, so final close cannot require
// allocation. The caller serializes changes with report transmission.
class MulticastSourceReports {
  public:
    static constexpr unsigned current_capacity = MulticastSourceAggregate::capacity;
    static constexpr unsigned history_capacity = current_capacity * 2;
    using Emit = bool (*)(void*, unsigned type, const uint32_t*, unsigned count);

    // The effective list must be sorted and unique; mode is EXCLUDE=0 or
    // INCLUDE=1. Failure preserves every pending record and the current list.
    int change(unsigned mode, const uint32_t*, unsigned count, unsigned robustness);
    // Production callers provide the aggregate to reserve hidden contributors
    // too. Admit a new owner only after this transaction succeeds.
    int change(const MulticastSourceAggregate&, unsigned robustness);
    int restart(unsigned robustness);
    void cancel();
    bool pending() const;

    // Transmit one logical round. Refused output preserves its cursor and
    // obligations; a later call continues that round. The emitter must not
    // reenter this object. The caller schedules later rounds while pending().
    bool transmit(unsigned max_sources, Emit, void*);

  private:
    struct Source {
        uint32_t address = 0;
        uint8_t remaining = 0;
        bool listed = false, reserved = false;
    };

    Source sources[history_capacity]{};
    unsigned used = 0, cursor = 0, round_count = 0;
    uint32_t round[history_capacity]{};
    uint8_t mode_remaining = 0;
    bool include = true, active = false;

    int update(unsigned mode, const uint32_t*, unsigned count, const uint32_t* retained,
               unsigned retained_count, unsigned robustness);
    Source& find(uint32_t address);
    void compact();
    void reset_round();
    bool forwards(const Source&) const;
};
} // namespace ax::ip4
