// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/barrier.cpp
 * @brief   Implement Linux memory barriers on the single x86-64 CPU.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Tracks expedited barrier registration per address space and applies the
 * processor barrier required by each supported command.
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
#include "mm/barrier.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
enum Command : uint32_t {
    query = 0,
    global = 1 << 0,
    global_expedited = 1 << 1,
    register_global_expedited = 1 << 2,
    private_expedited = 1 << 3,
    register_private_expedited = 1 << 4,
    private_sync_core = 1 << 5,
    register_private_sync_core = 1 << 6,
    get_registrations = 1 << 9,
};

constexpr uint32_t supported = global | global_expedited | register_global_expedited |
                               private_expedited | register_private_expedited | private_sync_core |
                               register_private_sync_core | get_registrations;
} // namespace

int memory_barrier(MemoryContext& memory, uint32_t command, uint32_t flags) {
    if (flags)
        return -22;

    switch (command) {
    case query:
        return supported;
    case get_registrations:
        return memory.barrier_registrations;
    case register_global_expedited:
    case register_private_expedited:
    case register_private_sync_core:
        memory.barrier_registrations |= command;
        return 0;
    case private_sync_core: {
        if (!(memory.barrier_registrations & register_private_sync_core))
            return -1;
        uint32_t leaf = 0;
        asm volatile("cpuid" : "+a"(leaf) : : "rbx", "rcx", "rdx", "memory");
        return 0;
    }
    case private_expedited:
        if (!(memory.barrier_registrations & register_private_expedited))
            return -1;
        [[fallthrough]];
    case global:
    case global_expedited:
        // Only this CPU can be executing user code. There are no peers to interrupt.
        asm volatile("mfence" ::: "memory");
        return 0;
    default:
        return -22;
    }
}
} // namespace ax
