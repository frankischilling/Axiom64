// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>

namespace ax {
enum class Resource : unsigned {
    cpu,
    file_size,
    data,
    stack,
    core,
    resident,
    processes,
    open_files,
    locked_memory,
    address_space,
    locks,
    pending_signals,
    message_queue,
    nice,
    realtime_priority,
    realtime_time,
    count
};

struct ResourceLimit {
    uint64_t soft, hard;
};

constexpr uint64_t resource_infinity = UINT64_MAX;
static_assert(sizeof(ResourceLimit) == 16);

// Each process owns one table. Threads share it; fork copies it and exec keeps it.
// The descriptor capacity is an implementation bound, independent of privilege.
class ProcessLimits {
  public:
    explicit ProcessLimits(uint64_t descriptor_capacity = 128);
    int exchange(unsigned resource, const ResourceLimit* replacement, ResourceLimit* previous,
                 bool privileged);
    uint64_t soft(Resource resource) const;

    uint64_t hard(Resource resource) const;

    int cpu_signal(uint64_t elapsed_ticks);

  private:
    uint64_t descriptor_capacity_;
    ResourceLimit values_[unsigned(Resource::count)];
};
} // namespace ax
