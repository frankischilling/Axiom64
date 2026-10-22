// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(int ok, const char* reason) {
    if (!ok) {
        printf("IPV6_STICKY_LOCAL_FAIL %s errno=%d\n", reason, errno);
        exit(90);
    }
}

static unsigned make_header(unsigned char* bytes, unsigned option, unsigned value) {
    memset(bytes, 0, 2048);
    bytes[0] = 250;
    if (option == 57) {
        bytes[1] = 2;
        bytes[2] = 2;
        bytes[3] = 1;
        bytes[4] = value;
        bytes[23] = 1;
        return 24;
    }
    bytes[2] = 0x1e;
    bytes[3] = 4;
    memset(bytes + 4, value, 4);
    return 8;
}

static void hex(const unsigned char* bytes, size_t size) {
    for (size_t at = 0; at < size; at++)
        printf("%02x", bytes[at]);
}

static void one(unsigned raw, unsigned drop, unsigned choice, unsigned variant, unsigned number) {
    static const unsigned options[] = {54, 55, 57, 59};
    unsigned option = options[choice];
    int fd = socket(AF_INET6, raw ? SOCK_RAW : SOCK_DGRAM, raw ? 58 : 0);
    check(fd >= 0, "actual description");
    int alias = dup(fd);
    check(alias >= 0, "shared description");
    unsigned char seed[2048], input[2048], original[2048];
    unsigned size = make_header(seed, option, 0x11);
    errno = 0;
    int seeded = variant == 0 ? 0 : setsockopt(fd, 41, option, seed, size);
    int seed_error = seeded < 0 ? errno : 0;
    size = make_header(input, option, 0x22);
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED, "owned guard pages");
    memset(pages, 0xa5, 8192);
    check(!fflush(stdout), "flush original parent output before fork");
    pid_t child = fork();
    check(child >= 0, "isolated observation");
    if (!child) {
        if (drop)
            check(!setuid(65534), "actual ordinary identity");
        const void* value = input;
        uint32_t length = size;
        int action = variant < 21 || variant >= 53;
        if (variant == 0 || variant == 2 || variant == 3 || variant == 20) {
            length = 0;
            value = variant == 3 ? (void*)(uintptr_t)1 : NULL;
        } else if (variant == 4) {
            value = NULL;
            length = 8;
        } else if (variant == 5) {
            value = (void*)(uintptr_t)1;
            length = 8;
        } else if (variant >= 6 && variant <= 10) {
            static const unsigned sizes[] = {1, 2, 7, 9, 16};
            length = sizes[variant - 6];
        } else if (variant == 11) {
            length = 2040;
            input[1] = 254;
        } else if (variant == 12) {
            length = 2048;
            input[1] = 255;
        } else if (variant == 13) {
            length = UINT32_MAX;
        } else if (variant == 14) {
            memcpy(pages + 4092, input, 4);
            check(!mprotect(pages + 4096, 4096, PROT_NONE), "protected set tail");
            value = pages + 4092;
            length = 8;
        } else if (variant == 15) {
            input[1] = 255;
        } else if (variant == 16 || variant == 62) {
            length += 8;
            memset(input + size, 0x77, 8);
        } else if (variant == 18) {
            check(!close(fd), "retire first alias");
            fd = -1;
        } else if (variant == 19) {
            input[1] = 255;
        } else if (variant >= 53 && variant <= 58) {
            memset(input, 0, sizeof(input));
            input[0] = 250;
            input[1] = 4;
            input[2] = 4;
            input[3] = 1;
            input[4] = 1;
            input[23] = 9;
            input[39] = 1;
            length = 40;
            if (variant == 54) {
                input[1] = 2;
                input[3] = input[4] = 0;
                length = 24;
            } else if (variant == 55) {
                input[3] = 2;
            } else if (variant == 56) {
                input[4] = 2;
            } else if (variant == 57 || variant == 58) {
                input[1] = 3;
                input[3] = input[4] = 0;
                input[24] = 0x1e;
                input[25] = variant == 57 ? 6 : 7;
                length = 32;
            }
        } else if (variant == 59) {
            input[2] = 0;
        } else if (variant == 60) {
            input[3] = 0;
        } else if (variant == 61) {
            input[1] = 1;
            length = 16;
        } else if (variant == 63) {
            memcpy(pages + 4096 - size, input, size);
            check(!mprotect(pages + 4096, 4096, PROT_NONE), "protected ignored input tail");
            value = pages + 4096 - size;
            length = size + 8;
        }
        memcpy(original, input, sizeof(input));
        errno = 0;
        long result = action ? syscall(SYS_setsockopt, alias, 41, option, value, length) : 0;
        int error = result < 0 ? errno : 0;
        unsigned unchanged = !memcmp(original, input, sizeof(input));
        if (variant == 17)
            memset(input, 0x88, sizeof(input));
        unsigned char output[2048], length_bytes[8];
        memset(output, 0xa5, sizeof(output));
        uint32_t capacity = 2048;
        void* destination = output;
        void* length_pointer = &capacity;
        if (variant >= 21 && variant <= 36) {
            static const unsigned capacities[] = {0, 1,  2,  3,  4,  5,  7,  8,
                                                  9, 23, 24, 25, 32, 63, 64, 2048};
            capacity = capacities[variant - 21];
        } else if (variant == 37 || variant == 38) {
            capacity = variant == 37 ? 0 : 64;
            destination = NULL;
        } else if (variant == 39) {
            length_pointer = NULL;
        } else if (variant == 40) {
            check(!mprotect(pages + 4096, 4096, PROT_NONE), "protected imported capacity");
            length_pointer = pages + 4096;
        } else if (variant >= 41 && variant <= 48) {
            static const unsigned prefixes[] = {0, 1, 2, 3, 4, 7, 8, 23};
            check(!mprotect(pages + 4096, 4096, PROT_READ), "read-only output suffix");
            destination = pages + 4096 - prefixes[variant - 41];
            capacity = 64;
        } else if (variant >= 49 && variant <= 52) {
            length_pointer = pages + 4096 - (variant - 49);
            capacity = 64;
            memcpy(length_pointer, &capacity, 4);
            check(!mprotect(pages + 4096, 4096, PROT_READ), "read-only result-length suffix");
        }
        memset(length_bytes, 0xa5, sizeof(length_bytes));
        errno = 0;
        long got = syscall(SYS_getsockopt, alias, 41, option, destination, length_pointer);
        int get_error = got < 0 ? errno : 0;
        if (variant >= 41 && variant <= 48)
            memcpy(output, destination, 64);
        if (variant >= 49 && variant <= 52) {
            memcpy(length_bytes, length_pointer, 8);
            memcpy(&capacity, length_pointer, 4);
        } else {
            memcpy(length_bytes, &capacity, 4);
        }
        unsigned char after[64];
        memset(after, 0xa5, sizeof(after));
        socklen_t after_length = sizeof(after);
        errno = 0;
        int after_result = getsockopt(alias, 41, option, after, &after_length);
        int after_error = after_result < 0 ? errno : 0;
        printf("IPV6_STICKY_LOCAL_CASE case=%u raw=%u drop=%u option=%u variant=%u uid=%u "
               "seeded=%d seed_errno=%d action=%d set_length=%u result=%ld errno=%d "
               "got=%ld get_errno=%d length=%u unchanged=%u lengthbytes=",
               number, raw, drop, option, variant, (unsigned)getuid(), seeded, seed_error, action,
               length, result, error, got, get_error, capacity, unchanged);
        hex(length_bytes, sizeof(length_bytes));
        printf(" output=");
        hex(output, sizeof(output));
        printf(" after_result=%d after_errno=%d after_length=%u after_output=", after_result,
               after_error, (unsigned)after_length);
        hex(after, sizeof(after));
        puts("");
        fflush(stdout);
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "completed sticky observation");
    check(!munmap(pages, 8192) && !close(alias) && !close(fd), "retired sticky resources");
}

int ipv6_sticky_controls_local(void) {
    struct utsname name;
    check(!uname(&name), "actual kernel identity");
    printf("IPV6_STICKY_LOCAL_KERNEL system=%s release=%s\n", name.sysname, name.release);
    unsigned cases = 0;
    for (unsigned raw = 0; raw < 2; raw++)
        for (unsigned drop = 0; drop < 2; drop++)
            for (unsigned option = 0; option < 4; option++)
                for (unsigned variant = 0; variant < 64; variant++)
                    one(raw, drop, option, variant, cases++);
    printf("IPV6_STICKY_LOCAL_DONE cases=%u\n", cases);
    return 0;
}

#ifndef IPV6_SEND_CONTROLS_INTEGRATED
int main(void) {
    return ipv6_sticky_controls_local();
}
#endif
