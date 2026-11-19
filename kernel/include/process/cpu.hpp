// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stdint.h>

namespace ax {
struct Process;
struct Task;

struct CpuUsage {
    uint64_t user_ticks, system_ticks;
};

// Switch accounting ownership with interrupts disabled. A null owner excludes idle time.
void cpu_account(Task* next = nullptr, bool userspace = false);

void cpu_refresh();

void cpu_depart(Task&);

CpuUsage cpu_usage(const Task&, bool thread);
CpuUsage cpu_waited_usage(const Process&);
void cpu_reap_child(Process&, const Process&);
uint64_t cpu_ticks(const Task&, bool thread);
} // namespace ax
