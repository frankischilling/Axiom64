// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"
#include "process/cpu.hpp"

namespace ax {
struct ResourceUsage {
    struct Timeval {
        int64_t seconds, microseconds;
    } user, system;

    int64_t counters[14];
};

static_assert(sizeof(ResourceUsage) == 144);

ResourceUsage linux_resource_usage(CpuUsage);
int64_t resource_usage_syscall(int who, uint64_t output);
int64_t resource_syscall(Frame*);
} // namespace ax
