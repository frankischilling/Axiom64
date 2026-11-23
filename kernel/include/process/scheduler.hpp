// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/process/scheduler.hpp
 * @brief   Coordinate scheduler entry, task ownership and shutdown.
 * @author  frankischilling
 * @date    2026-11-22
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

class KernelGuard {
  public:
    KernelGuard();
    ~KernelGuard();
    KernelGuard(const KernelGuard&) = delete;
    KernelGuard& operator=(const KernelGuard&) = delete;
};

void scheduler_admit(unsigned index, uint32_t apic_id);
void scheduler_start();
void scheduler_join();
void scheduler_poll_stop();
void scheduler_park_peers();
void scheduler_tick_peers();
void scheduler_idle();
bool scheduler_available(const Process&);
void scheduler_claim(Process&);
void scheduler_release();
unsigned scheduler_cpu_count();
unsigned scheduler_cpu_number();
} // namespace ax
