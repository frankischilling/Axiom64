// SPDX-License-Identifier: GPL-3.0-or-later
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
constexpr uint64_t page_mask = 0x000ffffffffff000;
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
void serial_init();
void putchar(char);
int serial_read();
void log(const char*, ...);
[[noreturn]] void panic(const char*);
[[noreturn]] void poweroff(int);
extern uint64_t direct_map;
inline void* physical(uint64_t p) {
    return reinterpret_cast<void*>(p + direct_map);
}
uint64_t page_alloc(size_t count = 1);
void page_free(uint64_t p, size_t count = 1);
void page_retain(uint64_t p, size_t count = 1);
bool page_shared(uint64_t p, size_t count = 1);
void* alloc(size_t);
void release(void*);

struct Frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t vector, error, rip, cs, rflags, rsp, ss;
};
static_assert(sizeof(Frame) == 22 * 8);
struct AddressSpace {
    uint64_t root = 0;
    uint64_t next_map = 0x100000000;
    bool create();
    void destroy();
    bool clone_from(const AddressSpace&);
    uint64_t* entry(uint64_t va, bool create = false);
    bool map(uint64_t va, size_t len, int prot);
    bool map_physical(uint64_t va, uint64_t pa, size_t len, int prot, bool external = false);
    void unmap(uint64_t va, size_t len);
    bool protect(uint64_t va, size_t len, int prot);
    bool valid(uint64_t va, size_t len, bool write = false) const;
    bool copy_in(void* dst, uint64_t src, size_t len) const;
    bool copy_out(uint64_t dst, const void* src, size_t len) const;
    bool string(uint64_t src, char* dst, size_t capacity) const;
};
void memory_init();
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
