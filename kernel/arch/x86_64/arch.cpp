// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/arch/x86_64/arch.cpp
 * @brief   x86-64 processor and interrupt setup.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Sets up processor tables and syscall entry and handles the architecture's
 * trap frames.
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
#include "core/base.hpp"
#include "arch/x86_64/cpu_local.hpp"
#include "arch/x86_64/interrupts.hpp"
#include "boot/boot.hpp"

namespace ax {
struct [[gnu::packed]] TablePointer {
    uint16_t size;
    uint64_t base;
};

struct [[gnu::packed]] Tss {
    uint32_t reserved;
    uint64_t rsp[3];
    uint64_t reserved2;
    uint64_t ist[7];
    uint64_t reserved3;
    uint16_t reserved4, iomap;
};

struct [[gnu::packed]] Gate {
    uint16_t low, selector;
    uint8_t ist, type;
    uint16_t middle;
    uint32_t high, reserved;
};

constexpr uint32_t fs_base_msr = 0xc0000100;
constexpr uint32_t gs_base_msr = 0xc0000101;
constexpr uint32_t gs_shadow_msr = 0xc0000102;

struct CpuTables {
    uint64_t gdt[7];
    Tss tss;
    CpuEntry entry;
};

static CpuTables bootstrap_tables, secondary_tables[max_boot_processors];
static Gate idt[256];
alignas(16) static uint8_t kernel_stack[128 * 1024], fault_stack[16 * 1024];
extern "C" {
void load_gdt(TablePointer*);
}

static void load_cpu_tables(CpuTables& tables, uint64_t kernel_top, uint64_t fault_top) {
    auto& gdt = tables.gdt;
    auto& tss = tables.tss;
    tss.rsp[0] = kernel_top;
    tss.ist[0] = fault_top;
    tss.iomap = sizeof(tss);
    gdt[1] = 0x00af9a000000ffff;
    gdt[2] = 0x00cf92000000ffff;
    gdt[3] = 0x00cff2000000ffff;
    gdt[4] = 0x00affa000000ffff;
    uint64_t b = uint64_t(&tss), limit = sizeof(tss) - 1;
    gdt[5] = limit | ((b & 0xffffff) << 16) | (0x89ull << 40) | (((b >> 24) & 255) << 56);
    gdt[6] = b >> 32;
    TablePointer gdtr{sizeof(gdt) - 1, uint64_t(gdt)};
    load_gdt(&gdtr);
}

static void init_cpu_entry(CpuEntry& entry, uint64_t kernel_top) {
    entry.kernel_stack_top = kernel_top;
    wrmsr(gs_base_msr, uint64_t(&entry));
    wrmsr(gs_shadow_msr, 0);
    TablePointer idtr{sizeof(idt) - 1, uint64_t(idt)};
    asm volatile("lidt %0" ::"m"(idtr));
    uint64_t cr0, cr4;
    asm volatile("mov %%cr0,%0" : "=r"(cr0));
    cr0 = (cr0 & ~4ull) | 0x10022;
    asm volatile("mov %0,%%cr0" ::"r"(cr0));
    asm volatile("mov %%cr4,%0" : "=r"(cr4));
    cr4 |= 0x600;
    asm volatile("mov %0,%%cr4" ::"r"(cr4));
    wrmsr(0xc0000080, rdmsr(0xc0000080) | 0x801);
    wrmsr(0xc0000081, (uint64_t(0x13) << 48) | (uint64_t(8) << 32));
    wrmsr(0xc0000082, uint64_t(syscall_entry));
    wrmsr(0xc0000084, 0x47700); // Clear IF, DF, TF, AC, NT on entry.
}

bool arch_secondary_task_slot_idle(unsigned slot) {
    return slot < max_boot_processors &&
           rdmsr(gs_base_msr) == uint64_t(&secondary_tables[slot].entry) &&
           rdmsr(gs_shadow_msr) == 0 && !current_task();
}

bool arch_init_secondary_tables(unsigned slot, uint64_t kernel_top, uint64_t fault_top) {
    if (slot >= max_boot_processors || !kernel_top || !fault_top)
        return false;
    auto& tables = secondary_tables[slot];
    load_cpu_tables(tables, kernel_top, fault_top);
    init_cpu_entry(tables.entry, kernel_top);
    TablePointer observed{}, observed_idt{};
    uint16_t task_register;
    asm volatile("sgdt %0" : "=m"(observed));
    asm volatile("sidt %0" : "=m"(observed_idt));
    asm volatile("str %0" : "=r"(task_register));
    return observed.base == uint64_t(tables.gdt) && observed.size == sizeof(tables.gdt) - 1 &&
           task_register == 0x28 && tables.tss.rsp[0] == kernel_top &&
           tables.tss.ist[0] == fault_top && observed_idt.base == uint64_t(idt) &&
           observed_idt.size == sizeof(idt) - 1 && arch_secondary_task_slot_idle(slot) &&
           rdmsr(0xc0000082) == uint64_t(syscall_entry);
}

void arch_init() {
    const auto kernel_stack_top = uint64_t(kernel_stack + sizeof(kernel_stack));
    load_cpu_tables(bootstrap_tables, kernel_stack_top,
                    uint64_t(fault_stack + sizeof(fault_stack)));
    for (unsigned i = 0; i < 256; i++) {
        uint64_t p = uint64_t(interrupt_table[i]);
        const uint8_t type = i == 3 ? 0xee : 0x8e; // Userspace can invoke INT3.
        idt[i] = {uint16_t(p),       8, uint8_t(i == 8 ? 1 : 0), type, uint16_t(p >> 16),
                  uint32_t(p >> 32), 0};
    }
    init_cpu_entry(bootstrap_tables.entry, kernel_stack_top);
    interrupt_init_legacy();
    log("CPU: GDT, TSS, IDT, SYSCALL and PIT initialized\n");
}

void arch_task(uint64_t fs, uint64_t gs) {
    wrmsr(fs_base_msr, fs);
    uint16_t selector;
    asm volatile("movw %%gs, %0" : "=r"(selector));
    if (selector) {
        // Reset a userspace selector without losing the active CPU-local base.
        const uint64_t cpu_base = rdmsr(gs_base_msr);
        asm volatile("movw %0, %%gs" : : "r"(uint16_t(0)) : "memory");
        wrmsr(gs_base_msr, cpu_base);
    }
    wrmsr(gs_shadow_msr, gs);
}
} // namespace ax
