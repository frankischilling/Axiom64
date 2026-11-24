// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/abi/linux/syscall_entry.cpp
 * @brief   Syscall entry, accounting, and scheduling.
 * @author  frankischilling
 * @date    2026-11-24
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
#include "core/time.hpp"
#include "drivers/platform/power_supply.hpp"
#include "ipc/ipc.hpp"
#include "process/cpu.hpp"
#include "process/scheduler.hpp"
#include "process/task.hpp"
#include "security/seccomp.hpp"

namespace ax {
int64_t dispatch_linux_syscall(Frame*, Task*);

extern "C" Frame* handle_syscall(Frame* f) {
    KernelGuard guard;
    auto* running = current_task();
    cpu_account(running);
    asm volatile("fxsave64 %0" : "=m"(running->fpu));
    clock_refresh();
    DeviceInventory::power_supply_refresh();
    const uint64_t number = f->rax;
    if (trace_syscalls)
        log("sys pid=%u nr=%u a=%x b=%x c=%x\n", uint64_t(running->pid), number, f->rdi, f->rsi,
            f->rdx);
    int64_t result = 0;
    const bool admitted = !running->seccomp_mode || seccomp_may_dispatch(*running, *f, result);
    if (admitted)
        result = dispatch_linux_syscall(f, running);
    cpu_refresh();
    epoll_notify();
    if (trace_syscalls)
        log("sys result=%d\n", result);
    const bool retry = admitted && result == would_block;
    if (retry) {
        f->rip -= 2;
        f->rax = number;
    } else if (!admitted || number != 15)
        f->rax = result;
    return schedule(f, number == 24 || retry || running->state != State::runnable);
}
} // namespace ax
