// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/arch/x86_64/tlb.cpp
 * @brief   Track loaded page tables and acknowledge invalidation requests.
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
#include "arch/x86_64/tlb.hpp"
#include "arch/x86_64/cpu_local.hpp"
#include "arch/x86_64/interrupts.hpp"
#include "boot/boot.hpp"
#include "core/base.hpp"
#include "drivers/platform/poll.hpp"

namespace ax {
namespace {
enum class TlbResult { idle, pending, invalidated, inactive, unsupported };

struct TlbRequest {
    uint64_t root = 0;
    uint64_t address = 0;
    TlbResult status = TlbResult::idle;

    TlbResult result() const {
        return __atomic_load_n(&status, __ATOMIC_ACQUIRE);
    }
};

struct CpuTlb {
    uint64_t loaded_root = 0;
    uint32_t apic_id = 0;
    TlbRequest request{};
};

// The BSP has slot zero. Secondary slots use the boot index plus one.
CpuTlb cpus[max_boot_processors + 1];
unsigned registered_cpus;
bool locked;
constexpr unsigned invalidation_timeout = 50;

// Hold this lock only for a CR3 switch or a snapshot. A receiver must never
// need the lock to acknowledge an interrupt.
struct RootLock {
    RootLock() {
        while (__atomic_test_and_set(&locked, __ATOMIC_ACQUIRE))
            asm volatile("pause");
    }

    ~RootLock() {
        __atomic_clear(&locked, __ATOMIC_RELEASE);
    }
};

bool pcid_active() {
    uint64_t cr4;
    asm volatile("mov %%cr4,%0" : "=r"(cr4));
    return cr4 & (1ull << 17);
}

void invalidate_local(uint64_t cr3, uint64_t address) {
    if (address == all_user_translations)
        write_cr3(cr3);
    else
        invalidate_local_page(address);
}

bool complete(const CpuTlb& cpu) {
    const auto result = cpu.request.result();
    return result == TlbResult::invalidated || result == TlbResult::inactive;
}
} // namespace

void register_tlb_cpu(uint32_t apic_id) {
    RootLock guard;
    auto& cpu = cpus[current_cpu_index()];
    cpu.apic_id = apic_id;
    cpu.loaded_root = read_cr3() & page_mask;
    ++registered_cpus;
}

void unregister_tlb_cpu() {
    RootLock guard;
    cpus[current_cpu_index()].loaded_root = 0;
    --registered_cpus;
}

void switch_address_space(uint64_t root) {
    RootLock guard;
    write_cr3(root);
    cpus[current_cpu_index()].loaded_root = root;
}

bool address_space_loaded(uint64_t root) {
    if (!root)
        return false;
    RootLock guard;
    if (registered_cpus == 1)
        return cpus[current_cpu_index()].loaded_root == root;
    for (const auto& cpu : cpus)
        if (cpu.loaded_root == root)
            return true;
    return false;
}

bool invalidate_user_translations(uint64_t root, uint64_t address, unsigned* remote_targets) {
    if (!root || (root & ~page_mask) ||
        (address != all_user_translations && (address >= user_limit || address % page_size)))
        return false;

    CpuTlb* targets[max_boot_processors];
    unsigned count = 0;
    const auto local = &cpus[current_cpu_index()];
    {
        // Page-table stores precede this snapshot. A later switch to this root
        // takes the same lock and reloads CR3 after those stores are visible.
        RootLock guard;
        if (registered_cpus > 1)
            for (auto& cpu : cpus)
                if (&cpu != local && cpu.loaded_root == root)
                    targets[count++] = &cpu;
    }
    if (remote_targets)
        *remote_targets = count;

    if (local->loaded_root == root) {
        if (pcid_active())
            return false;
        invalidate_local(read_cr3(), address);
    }
    if (!count)
        return true;

    for (unsigned i = 0; i < count; ++i) {
        auto& target = *targets[i];
        auto& request = target.request;
        if (request.result() == TlbResult::pending)
            return false;
        request.root = root;
        request.address = address;
        __atomic_store_n(&request.status, TlbResult::pending, __ATOMIC_RELEASE);
        if (!interrupt_send_tlb_ipi(target.apic_id))
            return false;
    }
    return DevicePoll::wait(
        [&] {
            for (unsigned i = 0; i < count; ++i)
                if (!complete(*targets[i]))
                    return false;
            return true;
        },
        invalidation_timeout);
}

void service_tlb_ipi() {
    auto& request = cpus[current_cpu_index()].request;
    if (request.result() != TlbResult::pending)
        return;
    auto result = TlbResult::unsupported;
    if (!pcid_active()) {
        result = TlbResult::inactive;
        const uint64_t cr3 = read_cr3();
        if ((cr3 & page_mask) == request.root) {
            invalidate_local(cr3, request.address);
            result = TlbResult::invalidated;
        }
    }
    __atomic_store_n(&request.status, result, __ATOMIC_RELEASE);
}

void sync_user_translations(uint64_t root, uint64_t address) {
    if (root && !invalidate_user_translations(root, address))
        panic("address-space invalidation did not complete");
}
} // namespace ax
