// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/process/cpu.hpp
 * @brief   Task CPU context operations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the hardware-facing helpers for entering and restoring task CPU
 * state.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once
#include <stdint.h>

namespace ax {
struct Process;
struct Task;

struct CpuUsage {
    uint64_t user_ticks, system_ticks;
};

struct LoadAverages {
    uint64_t one, five, fifteen;
};

// Sample runnable tasks from the timer interrupt, even when the CPU is idle.
void cpu_sample_load();
LoadAverages cpu_load_averages();

// Switch accounting ownership with interrupts disabled. A null owner excludes idle time.
void cpu_account(Task* next = nullptr, bool userspace = false);

void cpu_refresh();

void cpu_depart(Task&);

CpuUsage cpu_usage(const Task&, bool thread);
CpuUsage cpu_waited_usage(const Process&);
void cpu_reap_child(Process&, const Process&);
uint64_t cpu_ticks(const Task&, bool thread);
} // namespace ax
