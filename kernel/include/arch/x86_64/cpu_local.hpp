// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/arch/x86_64/cpu_local.hpp
 * @brief   Access the current CPU's entry state.
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
struct Task;

struct CpuEntry {
    uint64_t kernel_stack_top;
    uint64_t saved_user_rsp;
    Task* task;
};

// entry.asm uses these offsets while switching from the userspace stack.
static_assert(__builtin_offsetof(CpuEntry, kernel_stack_top) == 0);
static_assert(__builtin_offsetof(CpuEntry, saved_user_rsp) == 8);

bool arch_secondary_task_slot_idle(unsigned slot);

#if __STDC_HOSTED__
Task* current_task();
void set_current_task(Task*);
#else
// Only use these when the CPU-local GS base is active.
inline Task* current_task() {
    Task* task;
    asm volatile("movq %%gs:%c[slot], %[task]"
                 : [task] "=r"(task)
                 : [slot] "i"(__builtin_offsetof(CpuEntry, task)));
    return task;
}

inline void set_current_task(Task* task) {
    asm volatile("movq %[task], %%gs:%c[slot]"
                 :
                 : [task] "r"(task), [slot] "i"(__builtin_offsetof(CpuEntry, task))
                 : "memory");
}
#endif
} // namespace ax
