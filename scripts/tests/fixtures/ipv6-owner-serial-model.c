// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise query output across a diagnostic between separate output calls.
#define _GNU_SOURCE
#define main ownership_fixture_main
#include "userspace/tests/net/ipv6_address_ownership.c"
#undef main
#include <assert.h>
#include <stdarg.h>
#include <sys/resource.h>

static char observed[1024];
static size_t used;
static unsigned print_calls, write_calls;
static struct pending_control selected;

int __wrap_printf(const char* format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(observed + used, sizeof(observed) - used, format, arguments);
    va_end(arguments);
    assert(length >= 0 && (size_t)length < sizeof(observed) - used);
    used += length;
    if (!print_calls++) {
        const char diagnostic[] = "IPv6 duplicate address index=2\n";
        assert(sizeof(diagnostic) < sizeof(observed) - used);
        memcpy(observed + used, diagnostic, sizeof(diagnostic));
        used += sizeof(diagnostic) - 1;
    }
    return length;
}

ssize_t __wrap_write(int fd, const void* data, size_t length) {
    assert(fd == STDOUT_FILENO && !write_calls && !print_calls && length < sizeof(observed));
    memcpy(observed, data, length);
    observed[length] = 0;
    used = length;
    write_calls++;
    return length;
}

int __wrap_poll(struct pollfd* descriptors, nfds_t count, int timeout) {
    assert(count == 1 && timeout == 100 && descriptors[0].fd == 10);
    descriptors[0].revents = POLLIN;
    return 1;
}

ssize_t __wrap_recv(int fd, void* data, size_t length, int flags) {
    assert(fd == 10 && length >= 60 && flags == MSG_DONTWAIT);
    unsigned char reply[60] = {0};
    memcpy(reply, macs[0], 6);
    memcpy(reply + 6, selected.frame, 6);
    memcpy(reply + 12, selected.frame + 12, 8);
    reply[20] = 1;
    memcpy(data, reply, 60);
    return 60;
}

int main(void) {
    struct rlimit limit = {0};
    assert(!setrlimit(RLIMIT_CORE, &limit));
    packets[0] = 10;
    memcpy(macs[0], (unsigned char[6]){0x52, 0x54, 0, 0x12, 0x34, 0x10}, 6);
    selected.lane = 0;
    selected.stamp = 1230000000;
    selected.frame[19] = 37;
    selected.frame[20] = CONFLICT;
    selected.frame[21] = 3;
    uint32_t fields[] = {htonl(0x8c2), htonl(UINT32_MAX), htonl(UINT32_MAX)};
    memcpy(selected.frame + 24, fields, sizeof(fields));
    struct in6_addr address;
    assert(inet_pton(AF_INET6, "2001:db8::1", &address) == 1);
    memcpy(selected.frame + 36, &address, 16);
    control_wait(&selected);
    const char expected[] =
        "IPV6_OWNER_CONTROL lane=0 phase=37 kind=4 case=3 stage=0 flags=8c2 "
        "preferred=4294967295 valid=4294967295 target=20010db8000000000000000000000001 "
        "observed_ns=1230000000\n";
    if (write_calls != 1 || print_calls || used != sizeof(expected) - 1 ||
        strcmp(observed, expected)) {
        fprintf(stderr, "OWNERSHIP_SERIAL_SPLIT printf_calls=%u write_calls=%u\n", print_calls,
                write_calls);
        return 23;
    }
    return 0;
}
