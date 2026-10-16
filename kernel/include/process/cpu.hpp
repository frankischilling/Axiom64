// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stdint.h>

namespace ax {
struct Task;

// Switch accounting ownership with interrupts disabled. A null owner excludes idle time.
void cpu_account(Task* next = nullptr, bool userspace = false);

void cpu_refresh();

void cpu_depart(Task&);

uint64_t cpu_ticks(const Task&, bool thread);
} // namespace ax
