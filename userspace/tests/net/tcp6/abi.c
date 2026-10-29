// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
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
#include <unistd.h>

static int native_packet_precheck;
static int native_name_length_first;

static void require(int condition, const char* operation, unsigned detail) {
    if (!condition) {
        printf("TCP6_ABI_FAIL operation=%s detail=%u errno=%d\n", operation, detail, errno);
        exit(1);
    }
}

static int stream(void) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    require(fd >= 0, "IPv6 stream creation", 0);
    return fd;
}

static int expected_address(unsigned family, unsigned length, int connecting) {
    if (length < 2 || length > 128)
        return EINVAL;
    // This measured WSL kernel rejects AF_PACKET before the IPv6 protocol's
    // minimum-length check. Upstream Linux and Axiom64 check length first.
    if (native_packet_precheck && family == AF_PACKET)
        return EAFNOSUPPORT;
    if (connecting && family == AF_UNSPEC)
        return 0;
    if (length < 24)
        return EINVAL;
    if (family != AF_INET6)
        return EAFNOSUPPORT;
    return connecting ? EINPROGRESS : 0;
}

static unsigned addresses(uint16_t port) {
    const unsigned families[] = {AF_UNSPEC, AF_INET, AF_INET6, AF_PACKET};
    const unsigned lengths[] = {0, 1, 2, 16, 23, 24, 27, 28, 129};
    unsigned cases = 0;
    for (unsigned connecting = 0; connecting < 2; connecting++)
        for (unsigned family = 0; family < sizeof(families) / sizeof(*families); family++)
            for (unsigned at = 0; at < sizeof(lengths) / sizeof(*lengths); at++) {
                int fd = stream();
                uint8_t bytes[160] = {0};
                struct sockaddr_in6 address = {0};
                address.sin6_family = families[family];
                address.sin6_port = connecting ? port : 0;
                address.sin6_addr = in6addr_loopback;
                memcpy(bytes, &address, sizeof(address));
                errno = 0;
                long result = syscall(connecting ? SYS_connect : SYS_bind, fd, bytes, lengths[at]);
                int observed = result < 0 ? errno : 0;
                require(observed == expected_address(families[family], lengths[at], connecting),
                        connecting ? "connect address import" : "bind address import", cases);
                require(!close(fd), "close imported address", cases++);
            }
    return cases;
}

static unsigned only_options(void) {
    const unsigned lengths[] = {0, 1, 3, 4, 8};
    unsigned cases = 0;
    for (unsigned bound = 0; bound < 2; bound++)
        for (unsigned at = 0; at < sizeof(lengths) / sizeof(*lengths); at++) {
            int fd = stream(), value = 1;
            if (bound) {
                struct sockaddr_in6 address = {.sin6_family = AF_INET6};
                require(!bind(fd, (struct sockaddr*)&address, sizeof(address)), "bind V6ONLY",
                        cases);
            }
            errno = 0;
            int result = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, lengths[at]);
            int expected = bound || lengths[at] < 4 ? EINVAL : 0;
            require((result < 0 ? errno : 0) == expected, "set V6ONLY", cases);
            value = -1;
            socklen_t length = sizeof(value);
            require(!getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &length) &&
                        length == sizeof(value) && value == (expected ? 0 : 1),
                    "V6ONLY value after set", cases);
            require(!close(fd), "close V6ONLY", cases++);
        }
    return cases;
}

static unsigned names(void) {
    const uint32_t lengths[] = {0, 1, 2, 16, 27, 28, 128, UINT32_MAX};
    unsigned cases = 0;
    for (unsigned valid = 0; valid < 2; valid++)
        for (unsigned at = 0; at < sizeof(lengths) / sizeof(*lengths); at++) {
            int fd = stream();
            uint8_t bytes[128], expected[128];
            memset(bytes, 0xa7, sizeof(bytes));
            memset(expected, 0xa7, sizeof(expected));
            socklen_t length = lengths[at];
            int expected_error = ((int32_t)length < 0) ? EINVAL : length && !valid ? EFAULT : 0;
            errno = 0;
            long result =
                syscall(SYS_getsockname, fd, valid ? bytes : (void*)(uintptr_t)1, &length);
            require((result < 0 ? errno : 0) == expected_error, "getsockname result", cases);
            uint32_t wanted =
                !expected_error || (native_name_length_first && expected_error == EFAULT)
                    ? 28
                    : lengths[at];
            require(length == wanted, "getsockname length", cases);
            if (!expected_error && valid) {
                struct sockaddr_in6 empty = {.sin6_family = AF_INET6};
                size_t copied = lengths[at] < sizeof(empty) ? lengths[at] : sizeof(empty);
                memcpy(expected, &empty, copied);
            }
            require(!memcmp(bytes, expected, sizeof(bytes)), "getsockname copy and guard", cases);
            require(!close(fd), "close getsockname", cases++);
        }
    return cases;
}

static unsigned name_copy_order(void) {
    const uint32_t capacities[] = {0, 1, 28, UINT32_MAX};
    struct sockaddr_in6 empty = {.sin6_family = AF_INET6};
    long page = sysconf(_SC_PAGESIZE);
    require(page > 0, "name copy page size", 0);
    unsigned cases = 0;
    for (unsigned at = 0; at < 4; at++) {
        int fd = stream();
        socklen_t* length =
            mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        require(length != MAP_FAILED, "name readonly length allocation", cases);
        *length = capacities[at];
        require(!mprotect(length, page, PROT_READ), "name readonly length protection", cases);
        uint8_t bytes[128], expected[128];
        memset(bytes, 0xa7, sizeof(bytes));
        memset(expected, 0xa7, sizeof(expected));
        int negative = (int32_t)capacities[at] < 0;
        if (!negative && !native_name_length_first) {
            size_t count = capacities[at] < sizeof(empty) ? capacities[at] : sizeof(empty);
            memcpy(expected, &empty, count);
        }
        errno = 0;
        long result = syscall(SYS_getsockname, fd, bytes, length);
        require(result == -1 && errno == (negative ? EINVAL : EFAULT),
                "name readonly length result", cases);
        require(*length == capacities[at] && !memcmp(bytes, expected, sizeof(bytes)),
                "name readonly length preserves exact prior copy", cases);
        require(!munmap(length, page) && !close(fd), "name readonly cleanup", cases++);
    }
    for (unsigned at = 0; at < 4; at++) {
        int fd = stream();

        union {
            uint32_t alignment;
            uint8_t bytes[128];
        } output;

        uint8_t expected[128];
        memset(output.bytes, 0xa7, sizeof(output.bytes));
        memset(expected, 0xa7, sizeof(expected));
        memcpy(output.bytes, &capacities[at], 4);
        memcpy(expected, &capacities[at], 4);
        int negative = (int32_t)capacities[at] < 0;
        if (!negative) {
            uint32_t actual = sizeof(empty);
            size_t count = capacities[at] < sizeof(empty) ? capacities[at] : sizeof(empty);
            if (native_name_length_first)
                memcpy(expected, &actual, 4);
            memcpy(expected, &empty, count);
            if (!native_name_length_first)
                memcpy(expected, &actual, 4);
        }
        errno = 0;
        long result = syscall(SYS_getsockname, fd, output.bytes, output.bytes);
        require(result == (negative ? -1 : 0) && (!negative || errno == EINVAL),
                "name aliased result", cases);
        require(!memcmp(output.bytes, expected, sizeof(expected)), "name aliased exact bytes",
                cases);
        require(!close(fd), "name alias cleanup", cases++);
    }
    const unsigned prefixes[] = {1, 16, 27, 28};
    for (unsigned readonly = 0; readonly < 2; readonly++)
        for (unsigned at = 0; at < 4; at++) {
            int fd = stream();
            uint8_t* memory =
                mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            socklen_t* length =
                mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            require(memory != MAP_FAILED && length != MAP_FAILED, "name partial allocation", cases);
            memset(memory, 0xa7, page * 2);
            *length = sizeof(empty);
            require(!mprotect(memory + page, page, PROT_NONE), "name partial guard", cases);
            if (readonly)
                require(!mprotect(length, page, PROT_READ), "name partial readonly length", cases);
            uint8_t expected[28];
            memset(expected, 0xa7, sizeof(expected));
            if (!readonly || !native_name_length_first)
                memcpy(expected, &empty, prefixes[at]);
            uint8_t* bytes = memory + page - prefixes[at];
            errno = 0;
            long result = syscall(SYS_getsockname, fd, bytes, length);
            int fault = readonly || prefixes[at] < sizeof(empty);
            require(result == (fault ? -1 : 0) && (!fault || errno == EFAULT),
                    "name partial result", cases);
            require(*length == sizeof(empty) && !memcmp(bytes, expected, prefixes[at]),
                    "name partial exact prefix", cases);
            require(!munmap(memory, page * 2) && !munmap(length, page) && !close(fd),
                    "name partial cleanup", cases++);
        }
    return cases;
}

static unsigned option_copies(void) {
    const uint32_t capacities[] = {0, 1, 2, 3, 4, 8, 0x80000000, UINT32_MAX};
    const uint32_t lengths[] = {0, 1, 3, 4, 8, 0x80000000, UINT32_MAX};
    unsigned cases = 0;
    long page = sysconf(_SC_PAGESIZE);
    require(page > 0, "option page size", cases);
    uint8_t* memory =
        mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED, "option fault pages", cases);
    for (unsigned selected = 0; selected < 2; selected++) {
        int fd = stream(), value = (int)selected;
        require(!setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, 4), "option copy value", cases);
        for (unsigned at = 0; at < sizeof(capacities) / sizeof(*capacities); at++)
            for (unsigned valid = 0; valid < 2; valid++) {
                uint8_t bytes[8], expected[8];
                memset(bytes, 0xa5, sizeof(bytes));
                memset(expected, 0xa5, sizeof(expected));
                socklen_t length = capacities[at];
                uint32_t copied = length < 4 ? length : 4;
                errno = 0;
                long result = syscall(SYS_getsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY,
                                      valid ? bytes : NULL, &length);
                require((result < 0 ? errno : 0) == (!valid && copied ? EFAULT : 0),
                        "option truncated result", cases);
                require(length == copied, "option truncated length", cases);
                if (valid)
                    memcpy(expected, &value, copied);
                require(!memcmp(bytes, expected, sizeof(bytes)), "option truncated bytes", cases++);
            }
        for (unsigned prefix = 0; prefix < 4; prefix++) {
            memset(memory, 0xa5, (size_t)page * 2);
            uint8_t* destination = memory + page - prefix;
            require(!mprotect(memory + page, (size_t)page, PROT_NONE), "protect option value",
                    cases);
            socklen_t length = 8;
            errno = 0;
            long result =
                syscall(SYS_getsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY, destination, &length);
            int error = result < 0 ? errno : 0;
            require(!mprotect(memory + page, (size_t)page, PROT_READ | PROT_WRITE),
                    "restore option value", cases);
            uint8_t expected[4] = {0xa5, 0xa5, 0xa5, 0xa5};
            memcpy(expected, &value, prefix);
            require(error == EFAULT && length == 4 && !memcmp(destination, expected, 4),
                    "option value fault prefix and published length", cases++);
        }
        for (unsigned prefix = 0; prefix < 4; prefix++) {
            memset(memory, 0xa5, (size_t)page * 2);
            uint8_t* destination = memory + page - prefix;
            uint32_t capacity = 0x11223344, copied = 4;
            memcpy(destination, &capacity, 4);
            require(!mprotect(memory + page, (size_t)page, PROT_READ), "protect option length",
                    cases);
            uint8_t bytes[4] = {0xa5, 0xa5, 0xa5, 0xa5};
            errno = 0;
            long result =
                syscall(SYS_getsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY, bytes, destination);
            int error = result < 0 ? errno : 0;
            require(!mprotect(memory + page, (size_t)page, PROT_READ | PROT_WRITE),
                    "restore option length", cases);
            uint8_t expected[4], untouched[4] = {0xa5, 0xa5, 0xa5, 0xa5};
            memcpy(expected, &capacity, 4);
            memcpy(expected, &copied, prefix);
            require(error == EFAULT && !memcmp(destination, expected, 4) &&
                        !memcmp(bytes, untouched, 4),
                    "option length fault precedes value", cases++);
        }
        for (uint32_t capacity = 0; capacity <= 5; capacity++) {
            uint32_t shared = capacity, copied = capacity < 4 ? capacity : 4, expected = copied;
            memcpy(&expected, &value, copied);
            require(!syscall(SYS_getsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY, &shared, &shared) &&
                        shared == expected,
                    "option aliased length and value", cases++);
        }
        require(!close(fd), "close option copies", cases);
    }
    for (unsigned bound = 0; bound < 2; bound++)
        for (unsigned at = 0; at < sizeof(lengths) / sizeof(*lengths); at++)
            for (unsigned pointer = 0; pointer < 3; pointer++) {
                int fd = stream(), value = 1;
                require(!setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, 4),
                        "initial setter value", cases);
                if (bound) {
                    struct sockaddr_in6 address = {.sin6_family = AF_INET6};
                    require(!bind(fd, (struct sockaddr*)&address, sizeof(address)),
                            "bind setter option", cases);
                }
                require(!mprotect(memory + page, (size_t)page, PROT_NONE), "protect setter value",
                        cases);
                const void* input = pointer == 0   ? NULL
                                    : pointer == 1 ? (const void*)&value
                                                   : memory + page;
                int expected = (int32_t)lengths[at] < 0 || lengths[at] < 4 ? EINVAL
                               : pointer == 2                              ? EFAULT
                               : bound                                     ? EINVAL
                                                                           : 0;
                errno = 0;
                long result =
                    syscall(SYS_setsockopt, fd, IPPROTO_IPV6, IPV6_V6ONLY, input, lengths[at]);
                int error = result < 0 ? errno : 0;
                require(!mprotect(memory + page, (size_t)page, PROT_READ | PROT_WRITE),
                        "restore setter value", cases);
                socklen_t length = 4;
                value = -1;
                require(error == expected, "setter pointer and length ordering", cases);
                require(!getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &length) &&
                            length == 4 && value == (!expected && !pointer ? 0 : 1),
                        "setter failure preserves value", cases);
                require(!close(fd), "close setter copies", cases++);
            }
    require(!munmap(memory, (size_t)page * 2), "release option pages", cases);
    return cases;
}

int main(void) {
    struct utsname identity;
    require(!uname(&identity), "kernel identity", 0);
    native_packet_precheck = !strcmp(identity.sysname, "Linux") &&
                             !strcmp(identity.release, "6.6.87.2-microsoft-standard-WSL2");
    // Linux 7 publishes the true name length before attempting the address
    // copy. The guest retains the measured Linux 6.17 copy-order contract.
    native_name_length_first =
        !strcmp(identity.sysname, "Linux") && !strcmp(identity.release, "7.0.0-1017-azure");
    if (native_name_length_first)
        printf("TCP6_ABI_NATIVE_NAME_COPY kernel=7.0.0-1017-azure length_first=1\n");
    if (native_packet_precheck)
        printf("TCP6_ABI_NATIVE_PRECHECK kernel=6.6.87.2-microsoft-standard-WSL2 "
               "family=17 short_cases=6 errno=97\n");
    int listener = stream(), value = 1;
    require(!setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)),
            "listener V6ONLY", 0);
    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    require(!bind(listener, (struct sockaddr*)&address, sizeof(address)), "bind listener", 0);
    require(!listen(listener, 32), "listen", 0);
    socklen_t length = sizeof(address);
    require(!getsockname(listener, (struct sockaddr*)&address, &length) &&
                length == sizeof(address),
            "listener name", 0);
    unsigned address_cases = addresses(address.sin6_port);
    unsigned option_cases = only_options();
    unsigned name_cases = names();
    unsigned name_copy_cases = name_copy_order();
    require(name_copy_cases == 16, "complete name copy cases", name_copy_cases);
    printf("TCP6_NAME_COPY_PASS cases=%u length_first=%d\n", name_copy_cases,
           native_name_length_first);
    unsigned copy_cases = option_copies();
    require(!close(listener), "close listener", 0);
    printf("TCP6_ABI_PASS address_cases=%u option_cases=%u name_cases=%u copy_cases=%u\n",
           address_cases, option_cases, name_cases, copy_cases);
    return 0;
}
