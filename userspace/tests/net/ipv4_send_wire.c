// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_receive_wire_fixture.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

enum { ORDINARY = 36, WAITING = 6, CASES = 68 };

static unsigned current_lane, current_case;
static volatile sig_atomic_t signals;

static struct {
    atomic_int* done;
    long* result;
    int* error;
    uint64_t *began, *finished;
} pending;

void wire_check(int accepted, const char* operation) {
    if (!accepted) {
        printf("IPV4_SEND_WIRE_FAIL lane=%u case=%u operation=%s error=%d\n", current_lane,
               current_case, operation, errno);
        if (pending.done) {
            int done = atomic_load(pending.done);
            if (done)
                printf("IPV4_SEND_WIRE_WAIT_FAILURE lane=%u case=%u done=1 result=%ld error=%d "
                       "began_ns=%llu finished_ns=%llu\n",
                       current_lane, current_case, *pending.result, *pending.error,
                       (unsigned long long)*pending.began, (unsigned long long)*pending.finished);
            else
                printf("IPV4_SEND_WIRE_WAIT_FAILURE lane=%u case=%u done=0\n", current_lane,
                       current_case);
        }
        exit(1);
    }
}

void wire_hex(const void* pointer, size_t length) {
    const unsigned char* bytes = pointer;
    for (size_t at = 0; at < length; at++)
        printf("%02x", bytes[at]);
}

static uint64_t monotonic(void) {
    struct timespec value;
    wire_check(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic clock");
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

static void observe_retirement(void) {
    struct timespec resolution;
    wire_check(!clock_getres(CLOCK_MONOTONIC, &resolution) && resolution.tv_sec == 0 &&
                   resolution.tv_nsec > 0 && resolution.tv_nsec <= 10000000,
               "bounded actual monotonic clock resolution");
    // One resolution interval covers the unknown phase of a coarse clock.
    // Independent captures still require at least three complete seconds.
    struct timespec remaining = {.tv_sec = 3, .tv_nsec = resolution.tv_nsec};
    while (nanosleep(&remaining, &remaining))
        wire_check(errno == EINTR, "complete retired-output observation window");
}

static uint16_t checksum(const unsigned char* bytes, size_t length) {
    uint32_t value = 0;
    for (size_t at = 0; at < length; at += 2)
        value += (uint16_t)bytes[at] << 8 | (at + 1 < length ? bytes[at + 1] : 0);
    while (value >> 16)
        value = (value & 65535) + (value >> 16);
    return (uint16_t)~value;
}

static uint32_t target(unsigned lane, unsigned sequence) {
    if (sequence >= 50)
        return (wire_prefix(lane) & ~255u) + sequence + 1;
    return 0xcb007100 + lane * 64 + sequence + 1;
}

static struct sockaddr_in destination(unsigned lane, unsigned sequence) {
    return (struct sockaddr_in){.sin_family = AF_INET,
                                .sin_port = htons(49157),
                                .sin_addr.s_addr = htonl(target(lane, sequence))};
}

static void defaults(int fd, int ttl, int tos) {
    wire_check(!setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, 4) &&
                   !setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, 4),
               "description defaults");
}

static int limit(int fd) {
    int value = -1;
    socklen_t size = sizeof(value);
    errno = 0;
    int result = getsockopt(fd, IPPROTO_IP, IP_MTU, &value, &size);
    return result < 0 ? -errno : value;
}

static int description(unsigned kind, unsigned lane, unsigned sequence, int connected) {
    int fd = socket(AF_INET, (kind ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC, kind == 2 ? 1 : 17);
    wire_check(fd >= 0, "actual send description");
    defaults(fd, 63, 34);
    if (connected) {
        struct sockaddr_in address = destination(lane, sequence);
        wire_check(!connect(fd, (struct sockaddr*)&address, sizeof(address)),
                   "connected default route");
    }
    return fd;
}

static void append(unsigned char* bytes, size_t* length, int option, const void* value,
                   size_t size) {
    struct cmsghdr header = {
        .cmsg_len = CMSG_LEN(size), .cmsg_level = IPPROTO_IP, .cmsg_type = option};
    memcpy(bytes + *length, &header, sizeof(header));
    memcpy(bytes + *length + sizeof(header), value, size);
    *length += CMSG_SPACE(size);
}

static size_t controls(unsigned char* bytes, unsigned lane, unsigned scenario, int waiting) {
    memset(bytes, 0, 128);
    size_t length = 0;
    int ttl = 37, tos = 184;
    append(bytes, &length, IP_TTL, &ttl, 4);
    append(bytes, &length, IP_TOS, &tos, 4);
    struct in_pktinfo info = {.ipi_addr.s_addr = htonl(0xdeadbeef)};
    if (waiting) {
        if (scenario == 1)
            info.ipi_spec_dst.s_addr = htonl(wire_alias(lane));
    } else {
        info.ipi_ifindex =
            (int)wire_links[(scenario == 2 || scenario == 3 || scenario == 5) ? lane ^ 1 : lane]
                .index;
        if (scenario == 1 || scenario == 3 || scenario == 5)
            info.ipi_spec_dst.s_addr = htonl(wire_alias(lane));
        if (scenario == 4)
            info.ipi_spec_dst.s_addr = htonl(wire_alias(lane ^ 1));
    }
    append(bytes, &length, IP_PKTINFO, &info, sizeof(info));
    if (!waiting && scenario == 5) {
        memset(&info, 0, sizeof(info));
        append(bytes, &length, IP_PKTINFO, &info, sizeof(info));
    }
    return length;
}

static size_t payload(unsigned char* bytes, size_t size, unsigned kind, unsigned lane,
                      unsigned sequence, unsigned phase, unsigned number) {
    size_t offset = kind ? 8 : 0;
    for (size_t at = 0; at < size; at++)
        bytes[offset + at] =
            (unsigned char)(at * 19 + sequence * 7 + lane * 31 + phase * 11 + kind * 13);
    memcpy(bytes + offset, "SWIR", 4);
    bytes[offset + 4] = lane;
    bytes[offset + 5] = sequence;
    bytes[offset + 6] = phase;
    bytes[offset + 7] = kind;
    bytes[offset + 8] = number;
    if (kind) {
        memset(bytes, 0, 8);
        if (kind == 1) {
            uint16_t fields[] = {htons(51000 + lane * 64 + sequence), htons(49157),
                                 htons((uint16_t)(size + 8)), 0};
            memcpy(bytes, fields, 8);
        } else {
            bytes[0] = 253;
            bytes[4] = 0x6d;
            bytes[5] = 0x53;
            uint16_t sum = htons(checksum(bytes, size + 8));
            memcpy(bytes + 2, &sum, 2);
        }
    }
    return size + offset;
}

static void barrier(unsigned lane, unsigned sequence, unsigned phase) {
    unsigned char frame[60] = {2, 0x41, 0x58, 0x52, 0x58, lane};
    memcpy(frame + 6, wire_links[lane].mac, 6);
    frame[12] = 0x88;
    frame[13] = 0xb9;
    memcpy(frame + 14, "SCTL", 4);
    frame[18] = lane;
    frame[19] = sequence;
    frame[20] = phase;
    for (size_t at = 22; at < sizeof(frame); at++)
        frame[at] = (unsigned char)(at * 17 + sequence * 7 + lane * 31 + phase);
    wire_check(send(wire_links[lane].control, frame, sizeof(frame), 0) == sizeof(frame),
               "physical ownership barrier");
    unsigned char expected[60], reply[128];
    memcpy(expected, frame, sizeof(expected));
    memcpy(expected, frame + 6, 6);
    memcpy(expected + 6, frame, 6);
    expected[21] = 1;
    struct pollfd wait = {.fd = wire_links[lane].control, .events = POLLIN};
    wire_check(poll(&wait, 1, 3000) == 1 && (wait.revents & POLLIN),
               "original three-second barrier bound");
    wire_check(recv(wait.fd, reply, sizeof(reply), 0) == sizeof(expected) &&
                   !memcmp(reply, expected, sizeof(expected)),
               "actual peer ownership acknowledgement");
}

static void ordinary(unsigned lane, unsigned sequence) {
    unsigned kind = sequence / 12, named = sequence / 6 % 2, scenario = sequence % 6;
    wire_change_route(target(lane, sequence), wire_links[lane].index, 1);
    int fd = description(kind, lane, sequence, !named), alias = dup(fd);
    wire_check(alias >= 0, "shared description alias");
    int before = limit(alias);
    wire_check(before == (named ? -ENOTCONN : lane ? 1200 : 1400), "original default route MTU");
    unsigned char body[128], ancillary[128];
    size_t size = payload(body, 64, kind, lane, sequence, 0, 0);
    size_t length = scenario ? controls(ancillary, lane, scenario, 0) : 0;
    struct sockaddr_in address = destination(lane, sequence);
    struct iovec vector = {.iov_base = body, .iov_len = size};
    struct msghdr message = {.msg_name = named ? &address : NULL,
                             .msg_namelen = named ? 16 : 0,
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = ancillary,
                             .msg_controllen = length};
    barrier(lane, sequence, 0);
    errno = 0;
    long result = syscall(SYS_sendmsg, fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    int error = result < 0 ? errno : 0;
    printf("IPV4_SEND_WIRE_OUTPUT lane=%u case=%u kind=%u named=%u scenario=%u result=%ld error=%d "
           "mtu_before=%d mtu_after=%d control=",
           lane, sequence, kind, named, scenario, result, error, before, limit(alias));
    wire_hex(ancillary, length);
    puts("");
    wire_check(result == (long)size && limit(alias) == before,
               "transient output preserves default route");
    memset(body, 0xcc, sizeof(body));
    memset(ancillary, 0xdd, sizeof(ancillary));
    defaults(alias, 11, 8);
    wire_check(!close(fd), "close original after accepted queueing");
    barrier(lane, sequence, 1);
    defaults(alias, 63, 34);
    size = payload(body, 64, kind, lane, sequence, 1, 0);
    wire_check(sendto(alias, body, size, MSG_DONTWAIT, (struct sockaddr*)&address, 16) ==
                   (long)size,
               "clean later default send");
    barrier(lane, sequence, 2);
    wire_check(!close(alias), "final description close");
    wire_change_route(target(lane, sequence), wire_links[lane].index, 0);
}

struct Operation {
    int fd, error;
    long result;
    uint64_t began, finished;
    atomic_int tid, done;
    struct msghdr message;
    struct iovec vector;
    struct sockaddr_in address;
    unsigned char ancillary[128];
};

static void* sender(void* pointer) {
    struct Operation* operation = pointer;
    operation->began = monotonic();
    atomic_store(&operation->tid, (int)syscall(SYS_gettid));
    errno = 0;
    operation->result = syscall(SYS_sendmsg, operation->fd, &operation->message, MSG_NOSIGNAL);
    operation->error = operation->result < 0 ? errno : 0;
    operation->finished = monotonic();
    atomic_store(&operation->done, 1);
    return NULL;
}

static void sleeping(struct Operation* operation, unsigned lane, unsigned sequence) {
    uint64_t deadline = monotonic() + 1000000000;
    char name[96], status[4096];
    while (monotonic() < deadline && !atomic_load(&operation->done)) {
        int tid = atomic_load(&operation->tid);
        if (!tid) {
            sched_yield();
            continue;
        }
        snprintf(name, sizeof(name), "/proc/self/task/%d/status", tid);
        int fd = open(name, O_RDONLY | O_CLOEXEC);
        wire_check(fd >= 0, "actual worker task status");
        ssize_t size = read(fd, status, sizeof(status) - 1);
        wire_check(size > 0 && !close(fd), "complete worker task status");
        status[size] = 0;
        if (strstr(status, "\nState:\tS") && !atomic_load(&operation->done)) {
            printf("IPV4_SEND_WIRE_SLEEP lane=%u case=%u tid=%d monotonic_ns=%llu status=", lane,
                   sequence, tid, (unsigned long long)monotonic());
            wire_hex(status, (size_t)size);
            puts("");
            return;
        }
        sched_yield();
    }
    wire_check(0, "worker observed sleeping inside sendmsg");
}

static unsigned pressure(int fd, unsigned kind, unsigned lane, unsigned sequence, unsigned output) {
    int requested = 2048, actual = 0;
    socklen_t size = sizeof(actual);
    struct timeval timeout = {.tv_sec = 5};
    wire_check(!setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &requested, 4) &&
                   !getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &actual, &size) && actual > 0 &&
                   !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
               "finite socket memory pressure");
    unsigned char bytes[1200];
    struct sockaddr_in address = destination(lane, sequence);
    for (unsigned number = 0; number < 64; number++) {
        size_t length = payload(bytes, 1100, kind, lane, sequence, 2, number);
        errno = 0;
        long result;
        if (output) {
            unsigned char ancillary[64] = {0};
            size_t control_length = 0;
            struct in_pktinfo info = {.ipi_ifindex = (int)output};
            append(ancillary, &control_length, IP_PKTINFO, &info, sizeof(info));
            struct iovec vector = {.iov_base = bytes, .iov_len = length};
            struct msghdr message = {.msg_name = &address,
                                     .msg_namelen = 16,
                                     .msg_iov = &vector,
                                     .msg_iovlen = 1,
                                     .msg_control = ancillary,
                                     .msg_controllen = control_length};
            result = syscall(SYS_sendmsg, fd, &message, MSG_DONTWAIT);
        } else {
            result = sendto(fd, bytes, length, MSG_DONTWAIT, (struct sockaddr*)&address, 16);
        }
        if (result < 0) {
            wire_check(number > 0 && errno == (kind ? ENOBUFS : EAGAIN),
                       "native memory refusal class");
            printf("IPV4_SEND_WIRE_PRESSURE lane=%u case=%u kind=%u fills=%u buffer=%d error=%d\n",
                   lane, sequence, kind, number, actual, errno);
            return number;
        }
        wire_check(result == (long)length, "complete retained fill");
    }
    wire_check(0, "bounded actual pressure reached");
    return 0;
}

static void interrupted(int signal) {
    if (signal == SIGUSR1)
        signals++;
}

static void waiting(unsigned lane, unsigned sequence) {
    int retired = sequence < 42;
    unsigned scenario = retired ? sequence - ORDINARY : sequence - 44;
    wire_change_route_metric(target(lane, sequence), wire_links[lane].index, retired ? 0 : 10, 1);
    int fd = description(0, lane, sequence, 0), alias = dup(fd);
    wire_check(alias >= 0, "waiting description alias");
    barrier(lane, sequence, 0);
    unsigned fills = pressure(fd, 0, lane, sequence, 0);
    unsigned char* body =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    wire_check(body != MAP_FAILED, "waiting payload mapping");
    size_t length = payload(body, 1100, 0, lane, sequence, 3, 0);
    struct Operation operation = {.fd = fd,
                                  .address = destination(lane, sequence),
                                  .vector = {.iov_base = body, .iov_len = length}};
    size_t control_length = controls(operation.ancillary, lane, scenario, 1);
    operation.message = (struct msghdr){.msg_name = &operation.address,
                                        .msg_namelen = 16,
                                        .msg_iov = &operation.vector,
                                        .msg_iovlen = 1,
                                        .msg_control = operation.ancillary,
                                        .msg_controllen = control_length};
    printf("IPV4_SEND_WIRE_WAIT_INPUT lane=%u case=%u length=%zu control=", lane, sequence, length);
    wire_hex(operation.ancillary, control_length);
    puts("");
    pthread_t thread;
    pending.done = &operation.done;
    pending.result = &operation.result;
    pending.error = &operation.error;
    pending.began = &operation.began;
    pending.finished = &operation.finished;
    wire_check(!pthread_create(&thread, NULL, sender, &operation), "actual waiting sender thread");
    sleeping(&operation, lane, sequence);
    defaults(alias, 11, 8);
    if (retired)
        wire_change_route(target(lane, sequence), wire_links[lane].index, 0);
    wire_change_route_metric(target(lane, sequence), wire_links[lane ^ 1].index, retired ? 0 : 1,
                             1);
    wire_inventory_paths(lane, sequence, 1, target(lane, sequence), wire_links[lane ^ 1].index,
                         retired ? 1 : 2);
    if (scenario == 1) {
        wire_change_address(lane, wire_alias(lane), ":rxs", 0);
        wire_inventory(lane, sequence, 1, wire_alias(lane), 0, 0);
    }
    memset(operation.ancillary, 0xdd, sizeof(operation.ancillary));
    if (scenario == 2)
        payload(body, 1100, 0, lane, sequence, 4, 0);
    if (scenario == 3)
        wire_check(!mprotect(body, 4096, PROT_NONE), "withdraw waiting payload access");
    if (scenario == 4) {
        operation.vector = (struct iovec){.iov_base = (void*)1, .iov_len = 1};
        operation.message.msg_name = (void*)1;
        operation.message.msg_namelen = 1;
        operation.message.msg_iov = (void*)1;
        operation.message.msg_iovlen = 1025;
        operation.message.msg_control = (void*)1;
        operation.message.msg_controllen = 131072;
    }
    if (scenario == 5) {
        wire_check(!syscall(SYS_tgkill, getpid(), atomic_load(&operation.tid), SIGUSR1),
                   "interrupt actual retained send");
        uint64_t deadline = monotonic() + 1000000000;
        while (!atomic_load(&operation.done) && monotonic() < deadline)
            sched_yield();
        wire_check(atomic_load(&operation.done),
                   "signal completes interrupted send before release");
    } else {
        wire_check(!atomic_load(&operation.done), "send remains retained through mutations");
    }
    wire_check(!close(fd), "close original while request owns description");
    barrier(lane, sequence, 1);
    wire_check(!pthread_join(thread, NULL), "join actual completed sender");
    int expected = scenario == 3 ? EFAULT : scenario == 5 ? EINTR : 0;
    printf("IPV4_SEND_WIRE_WAIT lane=%u case=%u scenario=%u fills=%u result=%ld error=%d "
           "began_ns=%llu finished_ns=%llu signals=%d\n",
           lane, sequence, scenario, fills, operation.result, operation.error,
           (unsigned long long)operation.began, (unsigned long long)operation.finished,
           (int)signals);
    wire_check(operation.error == expected && operation.result == (expected ? -1 : (long)length),
               "actual retained send outcome");
    if (retired) {
        uint64_t began = monotonic();
        observe_retirement();
        uint64_t finished = monotonic();
        wire_check(finished - began >= 3000000000,
                   "original clocks cover full three-second retired-output observation");
        printf("IPV4_SEND_WIRE_RETIRED_WINDOW lane=%u case=%u began_ns=%llu finished_ns=%llu\n",
               lane, sequence, (unsigned long long)began, (unsigned long long)finished);
    }
    wire_check(!mprotect(body, 4096, PROT_READ | PROT_WRITE), "restore owned payload mapping");
    length = payload(body, 1100, 0, lane, sequence, 1, 0);
    struct sockaddr_in address = destination(lane, sequence);
    wire_check(sendto(alias, body, length, MSG_DONTWAIT, (struct sockaddr*)&address, 16) ==
                   (long)length,
               "later call selects replacement route and current defaults");
    barrier(lane, sequence, 2);
    wire_check(!close(alias) && !munmap(body, 4096), "retained request resources released");
    wire_change_route_metric(target(lane, sequence), wire_links[lane ^ 1].index, retired ? 0 : 1,
                             0);
    if (!retired)
        wire_change_route_metric(target(lane, sequence), wire_links[lane].index, 10, 0);
    if (scenario == 1)
        wire_change_address(lane, wire_alias(lane), ":rxs", 1);
    pending.done = NULL;
}

static void raw_pressure(unsigned lane, unsigned sequence) {
    unsigned kind = sequence - ORDINARY - WAITING + 1;
    wire_change_route(target(lane, sequence), wire_links[lane].index, 1);
    int fd = description(kind, lane, sequence, 0), alias = dup(fd);
    wire_check(alias >= 0, "raw pressure alias");
    barrier(lane, sequence, 0);
    pressure(fd, kind, lane, sequence, 0);
    unsigned char body[1200], ancillary[128];
    size_t length = payload(body, 1100, kind, lane, sequence, 3, 0);
    struct iovec vector = {.iov_base = body, .iov_len = length};
    struct sockaddr_in address = destination(lane, sequence);
    size_t control_length = controls(ancillary, lane, 0, 1);
    struct msghdr message = {.msg_name = &address,
                             .msg_namelen = 16,
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = ancillary,
                             .msg_controllen = control_length};
    errno = 0;
    long result = syscall(SYS_sendmsg, fd, &message, MSG_NOSIGNAL);
    int error = result < 0 ? errno : 0;
    printf("IPV4_SEND_WIRE_RAW_PRESSURE lane=%u case=%u kind=%u result=%ld error=%d\n", lane,
           sequence, kind, result, error);
    wire_check(result == -1 && error == ENOBUFS,
               "raw blocking call refuses pressure without waiting");
    int zero = 0;
    memcpy(ancillary + sizeof(struct cmsghdr), &zero, 4);
    vector.iov_base = (void*)1;
    errno = 0;
    result = syscall(SYS_sendmsg, fd, &message, MSG_NOSIGNAL);
    error = result < 0 ? errno : 0;
    printf("IPV4_SEND_WIRE_RAW_ORDER lane=%u case=%u kind=%u result=%ld error=%d\n", lane, sequence,
           kind, result, error);
    wire_check(result == -1 && error == EINVAL,
               "control validation precedes raw memory and payload refusal");
    defaults(alias, 11, 8);
    wire_check(!close(fd), "close original raw description");
    barrier(lane, sequence, 1);
    length = payload(body, 1100, kind, lane, sequence, 1, 0);
    wire_check(sendto(alias, body, length, MSG_DONTWAIT, (struct sockaddr*)&address, 16) ==
                   (long)length,
               "raw memory reclaimed after neighbor release");
    barrier(lane, sequence, 2);
    wire_check(!close(alias), "final raw close");
    wire_change_route(target(lane, sequence), wire_links[lane].index, 0);
}

static unsigned administrative(unsigned lane, int up) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    wire_check(fd >= 0 && !ioctl(fd, SIOCGIFFLAGS, &request), "read actual interface flags");
    if (up >= 0) {
        request.ifr_flags = (short)(up ? request.ifr_flags | IFF_UP : request.ifr_flags & ~IFF_UP);
        wire_check(!ioctl(fd, SIOCSIFFLAGS, &request) && !ioctl(fd, SIOCGIFFLAGS, &request),
                   "mutate and independently read interface administration");
    }
    wire_check(!close(fd), "release interface control description");
    return (unsigned)(unsigned short)request.ifr_flags;
}

static void lifetime_inventory(unsigned lane, unsigned sequence, unsigned phase, unsigned mode,
                               unsigned mutation) {
    uint32_t value = mode < 2 ? target(lane, sequence) : wire_prefix(lane) & ~255u;
    unsigned count = mode >= 4 ? 0 : 1, selected = wire_links[lane].index;
    if (phase == 1)
        count = 0;
    if (phase == 2) {
        if (mutation == 0 && mode < 2) {
            count = 2;
            selected = wire_links[lane ^ 1].index;
        } else if (mutation == 1 || mutation == 2) {
            count = mutation == 2 && mode < 2 ? 0 : 1;
        }
    }
    wire_inventory_prefix(lane, sequence, phase, value, mode < 2 ? 32 : 24, count ? selected : 0,
                          count);
    unsigned assigned = phase == 1 && mutation == 1 && mode >= 4 ? 0 : wire_links[lane].index;
    wire_inventory(lane, sequence, phase, wire_prefix(lane), 0, assigned);
}

static void lifetime(unsigned lane, unsigned sequence) {
    unsigned mode = (sequence - 50) / 3, mutation = (sequence - 50) % 3;
    int connected = mode & 1, bound = mode == 5, retired = mode < 4 && mutation != 0;
    if (mode < 2)
        wire_change_route_metric(target(lane, sequence), wire_links[lane].index, 10, 1);
    if (mode >= 4)
        wire_remove_prefix(lane);
    lifetime_inventory(lane, sequence, 0, mode, mutation);
    int fd = description(0, lane, sequence, 0), alias = dup(fd);
    wire_check(alias >= 0, "lifetime description alias");
    barrier(lane, sequence, 0);
    // The other adapter owns every fill. Its release keeps the worker asleep
    // throughout route, source-prefix and administrative transitions on this one.
    unsigned fills = pressure(fd, 0, lane, sequence, wire_links[lane ^ 1].index);
    if (bound) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        wire_check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
                   "connected interface fallback without an installed FIB route");
    }
    struct sockaddr_in address = destination(lane, sequence);
    if (connected)
        wire_check(!connect(fd, (struct sockaddr*)&address, sizeof(address)),
                   "connect while existing output still owns socket memory");
    unsigned char body[1200];
    size_t length = payload(body, 1100, 0, lane, sequence, 3, 0);
    struct Operation operation = {
        .fd = fd, .address = address, .vector = {.iov_base = body, .iov_len = length}};
    size_t control_length = controls(operation.ancillary, lane, 0, 1);
    if (mode == 4) {
        struct in_pktinfo info = {.ipi_ifindex = (int)wire_links[lane].index,
                                  .ipi_addr.s_addr = htonl(0xdeadbeef)};
        memcpy(operation.ancillary + 2 * CMSG_SPACE(4) + CMSG_LEN(0), &info, sizeof(info));
    }
    operation.message = (struct msghdr){.msg_name = connected ? NULL : &operation.address,
                                        .msg_namelen = connected ? 0 : 16,
                                        .msg_iov = &operation.vector,
                                        .msg_iovlen = 1,
                                        .msg_control = operation.ancillary,
                                        .msg_controllen = control_length};
    printf("IPV4_SEND_WIRE_LIFETIME_INPUT lane=%u case=%u mode=%u mutation=%u connected=%d "
           "bound=%d fill_index=%u length=%zu control=",
           lane, sequence, mode, mutation, connected, bound, wire_links[lane ^ 1].index, length);
    wire_hex(operation.ancillary, control_length);
    puts("");
    pthread_t thread;
    pending.done = &operation.done;
    pending.result = &operation.result;
    pending.error = &operation.error;
    pending.began = &operation.began;
    pending.finished = &operation.finished;
    wire_check(!pthread_create(&thread, NULL, sender, &operation), "lifetime sender thread");
    sleeping(&operation, lane, sequence);
    defaults(alias, 11, 8);
    if (mutation == 0) {
        wire_change_route_metric(target(lane, sequence), wire_links[lane ^ 1].index, 1, 1);
    } else if (mutation == 1) {
        if (mode < 2)
            wire_change_route_metric(target(lane, sequence), wire_links[lane].index, 10, 0);
        else if (mode < 4)
            wire_remove_prefix(lane);
        else
            wire_change_address(lane, wire_prefix(lane), ":rxp", 0);
        lifetime_inventory(lane, sequence, 1, mode, mutation);
        if (mode < 2) {
            wire_change_route_metric(target(lane, sequence), wire_links[lane].index, 10, 1);
        } else {
            if (mode < 4)
                wire_change_address(lane, wire_prefix(lane), ":rxp", 0);
            wire_change_address(lane, wire_prefix(lane), ":rxp", 1);
        }
    } else {
        unsigned before = administrative(lane, -1), down = administrative(lane, 0);
        wire_check((before & IFF_UP) && !(down & IFF_UP), "actual administrative withdrawal");
        lifetime_inventory(lane, sequence, 1, mode, mutation);
        unsigned up = administrative(lane, 1);
        wire_check(up & IFF_UP, "actual administrative restoration");
        wire_reopen_control(lane);
        printf("IPV4_SEND_WIRE_LIFETIME_LINK lane=%u case=%u before=%x down=%x up=%x\n", lane,
               sequence, before, down, up);
    }
    lifetime_inventory(lane, sequence, 2, mode, mutation);
    memset(operation.ancillary, 0xdd, sizeof(operation.ancillary));
    operation.vector = (struct iovec){.iov_base = (void*)1, .iov_len = 1};
    operation.message = (struct msghdr){.msg_name = (void*)1,
                                        .msg_namelen = 1,
                                        .msg_iov = (void*)1,
                                        .msg_iovlen = 1025,
                                        .msg_control = (void*)1,
                                        .msg_controllen = 131072};
    wire_check(!atomic_load(&operation.done),
               "lifetime worker stays asleep until independent release");
    wire_check(!close(fd), "original descriptor closes during retained lifetime send");
    barrier(lane, sequence, 1);
    wire_check(!pthread_join(thread, NULL), "join lifetime sender");
    int socket_error = -1;
    socklen_t error_size = sizeof(socket_error);
    wire_check(!getsockopt(alias, SOL_SOCKET, SO_ERROR, &socket_error, &error_size) &&
                   error_size == 4,
               "actual post-transition socket error");
    printf("IPV4_SEND_WIRE_LIFETIME lane=%u case=%u mode=%u mutation=%u fills=%u result=%ld "
           "error=%d socket_error=%d began_ns=%llu finished_ns=%llu\n",
           lane, sequence, mode, mutation, fills, operation.result, operation.error, socket_error,
           (unsigned long long)operation.began, (unsigned long long)operation.finished);
    wire_check(operation.result == (long)length && !operation.error && !socket_error,
               "retained lifetime send completes without a synthetic socket error");
    if (retired) {
        uint64_t began = monotonic();
        observe_retirement();
        uint64_t finished = monotonic();
        wire_check(finished - began >= 3000000000, "original three-second lifetime window");
        printf("IPV4_SEND_WIRE_LIFETIME_WINDOW lane=%u case=%u began_ns=%llu finished_ns=%llu\n",
               lane, sequence, (unsigned long long)began, (unsigned long long)finished);
    }
    length = payload(body, 1100, 0, lane, sequence, 1, 0);
    wire_check(sendto(alias, body, length, MSG_DONTWAIT, (struct sockaddr*)&address, 16) ==
                   (long)length,
               "later lifetime send uses current route and description defaults");
    barrier(lane, sequence, 2);
    wire_check(!close(alias), "release final lifetime description");
    if (mutation == 0)
        wire_change_route_metric(target(lane, sequence), wire_links[lane ^ 1].index, 1, 0);
    if (mode < 2 && mutation != 2)
        wire_change_route_metric(target(lane, sequence), wire_links[lane].index, 10, 0);
    // Reassignment restores even a deliberately deleted automatic prefix.
    wire_change_address(lane, wire_prefix(lane), ":rxp", 0);
    wire_change_address(lane, wire_prefix(lane), ":rxp", 1);
    pending.done = NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct utsname identity;
    wire_check(!uname(&identity), "actual kernel identity");
    printf("{\"kind\":\"kernel\",\"sysname\":\"%s\",\"release\":\"%s\"}\n", identity.sysname,
           identity.release);
    struct sigaction action = {.sa_handler = interrupted};
    sigemptyset(&action.sa_mask);
    wire_check(!sigaction(SIGUSR1, &action, NULL), "owned interruption handler");
    wire_configure();
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    wire_check(fd >= 0, "MTU control description");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        request.ifr_mtu = lane ? 1200 : 1400;
        wire_check(!ioctl(fd, SIOCSIFMTU, &request), "distinct actual device MTUs");
    }
    wire_check(!close(fd), "close MTU control");
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned sequence = 0; sequence < CASES; sequence++) {
            current_lane = lane;
            current_case = sequence;
            if (sequence >= 50)
                lifetime(lane, sequence);
            else if (sequence < ORDINARY)
                ordinary(lane, sequence);
            else if (sequence < ORDINARY + WAITING || sequence >= 44)
                waiting(lane, sequence);
            else
                raw_pressure(lane, sequence);
        }
    puts("IPV4_SEND_WIRE_DONE lanes=2 cases_each=68");
    return 0;
}
