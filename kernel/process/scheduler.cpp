// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/process/scheduler.cpp
 * @brief   Serialize shared kernel state while CPUs run userspace in parallel.
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
#include "process/scheduler.hpp"
#include "arch/x86_64/cpu_local.hpp"
#include "arch/x86_64/interrupts.hpp"
#include "arch/x86_64/tlb.hpp"
#include "boot/boot.hpp"
#include "core/base.hpp"
#include "drivers/platform/poll.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr unsigned no_cpu = ~0u;

struct SchedulerCpu {
    uint32_t apic_id = 0;
    unsigned number = 0;
    Process* process = nullptr;
    bool stopped = false;
};

SchedulerCpu cpus[max_boot_processors + 1];
unsigned cpu_slots[max_boot_processors + 1];
unsigned admitted = 1;
unsigned stop_owner = no_cpu;
bool started;
bool kernel_owned;

bool parallel() {
    return __atomic_load_n(&started, __ATOMIC_ACQUIRE) && admitted > 1;
}

void lock_kernel() {
    if (!parallel())
        return;
    while (__atomic_test_and_set(&kernel_owned, __ATOMIC_ACQUIRE)) {
        scheduler_poll_stop();
        // The owner can be waiting for an invalidation from this CPU.
        service_tlb_ipi();
        asm volatile("pause");
    }
    scheduler_poll_stop();
}

void unlock_kernel() {
    if (parallel())
        __atomic_clear(&kernel_owned, __ATOMIC_RELEASE);
}
} // namespace

KernelGuard::KernelGuard() {
    lock_kernel();
}

KernelGuard::~KernelGuard() {
    unlock_kernel();
}

void scheduler_admit(unsigned index, uint32_t apic_id) {
    cpus[index].apic_id = apic_id;
    cpus[index].number = admitted;
    cpu_slots[admitted++] = index;
}

void scheduler_start() {
    cpus[0].apic_id = arch_current_apic_id();
    if (admitted > 1)
        log("SMP: scheduler online=%u\n", uint64_t(admitted));
    __atomic_store_n(&started, true, __ATOMIC_RELEASE);
}

void scheduler_join() {
    while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE))
        asm volatile("sti; hlt; cli" ::: "memory");
    if (!cpus[current_cpu_index()].number)
        return;
    Frame* frame;
    {
        KernelGuard guard;
        frame = schedule(nullptr, true);
    }
    enter_user(frame);
}

void scheduler_poll_stop() {
    if (!parallel())
        return;
    const unsigned owner = __atomic_load_n(&stop_owner, __ATOMIC_ACQUIRE);
    const unsigned index = current_cpu_index();
    if (owner == no_cpu || owner == index || (index && !cpus[index].number))
        return;
    activate_kernel_memory();
    __atomic_store_n(&cpus[index].stopped, true, __ATOMIC_RELEASE);
    for (;;)
        asm volatile("hlt");
}

void scheduler_park_peers() {
    if (!parallel())
        return;
    const unsigned index = current_cpu_index();
    __atomic_store_n(&stop_owner, index, __ATOMIC_RELEASE);
    for (unsigned cpu = 0; cpu < admitted; ++cpu) {
        const unsigned slot = cpu_slots[cpu];
        if (slot != index && !interrupt_send_scheduler_ipi(cpus[slot].apic_id))
            panic("cannot stop scheduler CPU");
    }
    if (!DevicePoll::wait(
            [&] {
                for (unsigned cpu = 0; cpu < admitted; ++cpu) {
                    const unsigned slot = cpu_slots[cpu];
                    if (slot != index && !__atomic_load_n(&cpus[slot].stopped, __ATOMIC_ACQUIRE))
                        return false;
                }
                return true;
            },
            50))
        panic("scheduler CPU did not stop");
}

void scheduler_tick_peers() {
    if (parallel())
        for (unsigned cpu = 1; cpu < admitted; ++cpu)
            if (!interrupt_send_scheduler_ipi(cpus[cpu_slots[cpu]].apic_id))
                panic("cannot deliver scheduler tick");
}

void scheduler_idle() {
    unlock_kernel();
    asm volatile("sti; hlt; cli" ::: "memory");
    lock_kernel();
}

bool scheduler_available(const Process& process) {
    return !parallel() || process.running_cpu == no_cpu;
}

void scheduler_claim(Process& process) {
    if (!parallel())
        return;
    const unsigned index = current_cpu_index();
    if (process.running_cpu != no_cpu || cpus[index].process)
        panic("process already assigned");
    process.running_cpu = index;
    cpus[index].process = &process;
}

void scheduler_release() {
    if (!parallel())
        return;
    auto& cpu = cpus[current_cpu_index()];
    if (cpu.process) {
        cpu.process->running_cpu = no_cpu;
        cpu.process = nullptr;
    }
}

unsigned scheduler_cpu_count() {
    return parallel() ? admitted : 1;
}

unsigned scheduler_cpu_number() {
    return parallel() ? cpus[current_cpu_index()].number : 0;
}
} // namespace ax
