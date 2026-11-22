// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/core/base.hpp
 * @brief   Kernel core types and runtime interfaces.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines shared scalar types, page constants, low-level runtime functions, and
 * memory allocation declarations.
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
#include <stddef.h>
#include <stdint.h>

extern "C" void* memcpy(void*, const void*, size_t);

extern "C" void* memset(void*, int, size_t);

extern "C" void* memmove(void*, const void*, size_t);

extern "C" int memcmp(const void*, const void*, size_t);

extern "C" size_t strlen(const char*);

extern "C" int strcmp(const char*, const char*);

namespace ax {
constexpr uint64_t page_size = 4096;
constexpr uint64_t user_limit = 0x0000800000000000;
constexpr size_t mmap_length_limit = 256 * 1024 * 1024;
constexpr uint64_t page_mask = 0x000ffffffffff000;
// Software bit outside the x86-64 physical-address field: mapping may not gain execution.
constexpr uint64_t page_no_execute = 1ull << 52;
constexpr uint64_t page_private = 1ull << 53, page_stack = 1ull << 54;
constexpr uint64_t page_file = 1ull << 55, page_file_access = 1ull << 56,
                   page_file_write = 1ull << 57, page_file_cow = 1ull << 58;
// Non-file entries reuse the file access bit to identify private anonymous mmap pages.
constexpr uint64_t page_anonymous = page_file_access;
constexpr uint64_t page_software =
    0xe00 | page_no_execute | page_private | page_stack | page_anonymous;

constexpr uint64_t align_down(uint64_t x) {
    return x & ~(page_size - 1);
}

constexpr uint64_t align_up(uint64_t x) {
    return (x + page_size - 1) & ~(page_size - 1);
}

template <class T> constexpr T min(T a, T b) {
    return a < b ? a : b;
}

template <class T> constexpr T max(T a, T b) {
    return a > b ? a : b;
}

inline void out8(uint16_t p, uint8_t v) {
    asm volatile("outb %0,%1" ::"a"(v), "Nd"(p));
}

inline uint8_t in8(uint16_t p) {
    uint8_t v;
    asm volatile("inb %1,%0" : "=a"(v) : "Nd"(p));
    return v;
}

inline void out16(uint16_t p, uint16_t v) {
    asm volatile("outw %0,%1" ::"a"(v), "Nd"(p));
}

inline uint16_t in16(uint16_t p) {
    uint16_t v;
    asm volatile("inw %1,%0" : "=a"(v) : "Nd"(p));
    return v;
}

inline void out32(uint16_t p, uint32_t v) {
    asm volatile("outl %0,%1" ::"a"(v), "Nd"(p));
}

inline uint32_t in32(uint16_t p) {
    uint32_t v;
    asm volatile("inl %1,%0" : "=a"(v) : "Nd"(p));
    return v;
}

inline uint64_t physical_address_limit() {
    uint32_t a = 0x80000000, b, c, d;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    if (a < 0x80000008)
        return 1ull << 36;
    a = 0x80000008;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    const auto bits = a & 0xff;
    return 1ull << (bits < 32 ? 32 : (bits > 52 ? 52 : bits));
}

inline uint64_t rdmsr(uint32_t m) {
    uint32_t a, d;
    asm volatile("rdmsr" : "=a"(a), "=d"(d) : "c"(m));
    return (uint64_t(d) << 32) | a;
}

inline void wrmsr(uint32_t m, uint64_t v) {
    asm volatile("wrmsr" ::"c"(m), "a"(uint32_t(v)), "d"(uint32_t(v >> 32)));
}

inline uint64_t read_cr3() {
    uint64_t v;
    asm volatile("mov %%cr3,%0" : "=r"(v));
    return v;
}

inline void write_cr3(uint64_t v) {
    asm volatile("mov %0,%%cr3" ::"r"(v) : "memory");
}

void putchar(char);

void log(const char*, ...);

[[noreturn]] void panic(const char*);

[[noreturn]] void poweroff(int);

extern uint64_t direct_map;

inline void* physical(uint64_t p) {
    return reinterpret_cast<void*>(p + direct_map);
}

struct PhysicalMemoryStats {
    uint64_t total, free, shared;
};

PhysicalMemoryStats physical_memory_stats();

uint64_t page_alloc(size_t count = 1);

void page_account_shared(uint64_t p, size_t count = 1);

void page_free(uint64_t p, size_t count = 1);

void page_retain(uint64_t p, size_t count = 1);
bool page_try_retain(uint64_t p);

bool page_shared(uint64_t p, size_t count = 1);
unsigned page_reference_count(uint64_t p);

void* alloc(size_t);

void release(void*);

struct Frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t vector, error, rip, cs, rflags, rsp, ss;
};

static_assert(sizeof(Frame) == 22 * 8);

struct FileMapping;

struct AddressSpace {
    uint64_t root = 0;
    uint64_t next_map = 0x100000000;
    FileMapping* file_mappings = nullptr;

    bool create();

    void destroy();

    bool clone_from(const AddressSpace&);

    uint64_t* entry(uint64_t va, bool create = false);

    uint64_t mapped_size(uint64_t start = 0, uint64_t length = user_limit) const;
    uint64_t resident_size() const;

    uint64_t find_unmapped(size_t length) const;

    uint64_t private_writable_size(uint64_t start = 0, uint64_t length = user_limit,
                                   bool make_writable = false) const;

    bool map(uint64_t va, size_t len, int prot, uint64_t mapping_flags = page_private);
    bool move_anonymous_mapping(uint64_t source, size_t old_size, uint64_t destination,
                                size_t new_size, int protection);
    void move_prepared_pages(uint64_t source, uint64_t destination, size_t size);

    bool prepare_mapping(uint64_t va, size_t len);

    bool map_physical(uint64_t va, uint64_t pa, size_t len, int prot, bool external = false);

    void unmap(uint64_t va, size_t len);

    bool protect(uint64_t va, size_t len, int prot);

    bool valid(uint64_t va, size_t len, bool write = false) const;
    uint64_t retain_readable_page(uint64_t address);

    bool copy_in(void* dst, uint64_t src, size_t len) const;

    bool copy_out(uint64_t dst, const void* src, size_t len) const;

    bool string(uint64_t src, char* dst, size_t capacity) const;
};

void memory_init();

void activate_kernel_memory();

// Supervisor-only, uncached mappings for device registers; length is bounded to 1 MiB.
void* map_mmio(uint64_t address, size_t length);

void arch_init();

void arch_task(uint64_t fs);

extern "C" [[noreturn]] void enter_user(Frame*);

extern "C" void syscall_entry();

extern "C" void* interrupt_table[];

extern "C" Frame* handle_trap(Frame*);

extern "C" Frame* handle_syscall(Frame*);
} // namespace ax
