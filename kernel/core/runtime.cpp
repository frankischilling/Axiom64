// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/base.hpp"
#include "drivers/platform/power.hpp"
#include "fs/vfs.hpp"
#include <stdarg.h>

extern "C" void* memcpy(void* d, const void* s, size_t n) {
    auto target = d;
    auto source = s;
    asm volatile("rep movsb" : "+D"(target), "+S"(source), "+c"(n)::"memory");
    return d;
}

extern "C" void* memset(void* d, int c, size_t n) {
    auto target = d;
    asm volatile("rep stosb" : "+D"(target), "+c"(n) : "a"(static_cast<uint8_t>(c)) : "memory");
    return d;
}

extern "C" void* memmove(void* d, const void* s, size_t n) {
    auto a = (unsigned char*)d;
    auto b = (const unsigned char*)s;
    if (a < b)
        return memcpy(d, s, n);
    while (n) {
        --n;
        a[n] = b[n];
    }
    return d;
}

extern "C" int memcmp(const void* a, const void* b, size_t n) {
    auto x = (const unsigned char*)a;
    auto y = (const unsigned char*)b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i])
            return x[i] - y[i];
    return 0;
}

extern "C" size_t strlen(const char* s) {
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

extern "C" int strcmp(const char* a, const char* b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

extern "C" void __cxa_pure_virtual() {
    ax::panic("pure virtual call");
}

namespace ax {
void serial_init() {
    out8(0x3f9, 0);
    out8(0x3fb, 0x80);
    out8(0x3f8, 1);
    out8(0x3f9, 0);
    out8(0x3fb, 3);
    out8(0x3fa, 0xc7);
    out8(0x3fc, 0x0b);
}

void putchar(char c) {
    if (c == '\n')
        putchar('\r');
    while (!(in8(0x3fd) & 0x20))
        asm volatile("pause");
    out8(0x3f8, c);
}

int serial_read() {
    return (in8(0x3fd) & 1) ? in8(0x3f8) : -1;
}

static void number(uint64_t v, unsigned base) {
    char b[32];
    size_t n = 0;
    do {
        b[n++] = "0123456789abcdef"[v % base];
        v /= base;
    } while (v);
    while (n)
        putchar(b[--n]);
}

void log(const char* s, ...) {
    va_list ap;
    va_start(ap, s);
    while (*s) {
        if (*s++ != '%') {
            putchar(s[-1]);
            continue;
        }
        switch (*s++) {
        case 's': {
            const char* p = va_arg(ap, const char*);
            if (!p)
                p = "(null)";
            while (*p)
                putchar(*p++);
            break;
        }
        case 'x':
            number(va_arg(ap, uint64_t), 16);
            break;
        case 'u':
            number(va_arg(ap, uint64_t), 10);
            break;
        case 'd': {
            int64_t v = va_arg(ap, int64_t);
            if (v < 0) {
                putchar('-');
                number(uint64_t(0) - uint64_t(v), 10);
            } else
                number(v, 10);
            break;
        }
        case 'c':
            putchar(va_arg(ap, int));
            break;
        default:
            putchar('%');
            break;
        }
    }
    va_end(ap);
}

[[noreturn]] void panic(const char* s) {
    log("\nPANIC: %s\n", s);
    out32(0xf4, 0x7f);
    asm volatile("cli");
    for (;;)
        asm volatile("hlt");
}

[[noreturn]] void poweroff(int status) {
    int error = shutdown_filesystems();
    if (error) {
        log("FILESYSTEM_SHUTDOWN_FAIL errno=%d\n", int64_t(-error));
        status = 1;
    }
    log("AXIOM64_EXIT status=%d\n", int64_t(status));
    out32(0xf4, status ? 1 : 0);
    platform_poweroff();
    asm volatile("cli");
    for (;;)
        asm volatile("hlt");
}
} // namespace ax
