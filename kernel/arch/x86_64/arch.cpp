// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/base.hpp"

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

static uint64_t gdt[7];
static Gate idt[256];
static Tss tss;
alignas(16) static uint8_t kernel_stack[128 * 1024], fault_stack[16 * 1024];
extern "C" {
uint64_t kernel_stack_top;

void load_gdt(TablePointer*);
}

void arch_init() {
    kernel_stack_top = uint64_t(kernel_stack + sizeof(kernel_stack));
    tss.rsp[0] = kernel_stack_top;
    tss.ist[0] = uint64_t(fault_stack + sizeof(fault_stack));
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
    for (unsigned i = 0; i < 48; i++) {
        uint64_t p = uint64_t(interrupt_table[i]);
        idt[i] = {uint16_t(p),       8, uint8_t(i == 8 ? 1 : 0), 0x8e, uint16_t(p >> 16),
                  uint32_t(p >> 32), 0};
    }
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
    // PIC remap; only the 100 Hz PIT interrupt is enabled.
    out8(0x20, 0x11);
    out8(0xa0, 0x11);
    out8(0x21, 32);
    out8(0xa1, 40);
    out8(0x21, 4);
    out8(0xa1, 2);
    out8(0x21, 1);
    out8(0xa1, 1);
    out8(0x21, 0xfe);
    out8(0xa1, 0xff);
    out8(0x43, 0x36);
    out8(0x40, uint8_t(11932));
    out8(0x40, uint8_t(11932 >> 8));
    log("CPU: GDT, TSS, IDT, SYSCALL and PIT initialized\n");
}

void arch_task(uint64_t fs) {
    wrmsr(0xc0000100, fs);
}
} // namespace ax
