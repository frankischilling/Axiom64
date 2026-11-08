// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static unsigned current_case, lane, device, transport, survival, sequence;
static uint32_t local, peer, guard;
static const char* interface;

static void require(int condition, const char* what) {
    if (!condition) {
        fprintf(stderr, "LIFETIME_WIRE_FAIL case=%u operation=%s errno=%d\n", current_case, what,
                errno);
        exit(1);
    }
}

static uint64_t now(clockid_t clock) {
    struct timespec value;
    require(!clock_gettime(clock, &value), "actual clock");
    return (uint64_t)value.tv_sec * 1000000000 + (uint64_t)value.tv_nsec;
}

static void event(const char* phase, long long status) {
    uint64_t monotonic = now(CLOCK_MONOTONIC), realtime = now(CLOCK_REALTIME);
    printf("LIFETIME_WIRE_EVENT {\"case\":%u,\"lane\":%u,\"index\":%u,\"transport\":%u,"
           "\"survival\":%u,\"source\":%u,\"peer\":%u,\"guard\":%u,\"phase\":\"%s\","
           "\"status\":%lld,\"monotonic_ns\":%llu,\"realtime_ns\":%llu}\n",
           current_case, lane, device, transport, survival, local, peer, guard, phase, status,
           (unsigned long long)monotonic, (unsigned long long)realtime);
}

static void hex(const void* input, size_t length) {
    const unsigned char* bytes = input;
    for (size_t at = 0; at < length; at++)
        printf("%02x", bytes[at]);
}

static void received(unsigned tag, const void* bytes, size_t length, uint64_t before,
                     uint64_t real_before) {
    uint64_t after = now(CLOCK_MONOTONIC), real_after = now(CLOCK_REALTIME);
    printf("LIFETIME_WIRE_RECEIVE {\"case\":%u,\"tag\":%u,\"before_ns\":%llu,\"after_ns\":%llu,"
           "\"realtime_before_ns\":%llu,\"realtime_after_ns\":%llu,\"bytes\":\"",
           current_case, tag, (unsigned long long)before, (unsigned long long)after,
           (unsigned long long)real_before, (unsigned long long)real_after);
    hex(bytes, length);
    puts("\"}");
}

static size_t attribute(unsigned char* bytes, size_t at, unsigned type, const void* value,
                        size_t length) {
    struct rtattr field = {.rta_len = (unsigned short)(length + 4),
                           .rta_type = (unsigned short)type};
    memcpy(bytes + at, &field, 4);
    memcpy(bytes + at + 4, value, length);
    return at + RTA_ALIGN(length + 4);
}

static int submit(unsigned char* bytes, size_t size) {
    struct nlmsghdr* message = (void*)bytes;
    message->nlmsg_len = (unsigned)size;
    message->nlmsg_seq = ++sequence;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    require(fd >= 0, "control description");
    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    require(!bind(fd, (struct sockaddr*)&address, sizeof(address)), "control port");
    socklen_t available = sizeof(address);
    require(!getsockname(fd, (struct sockaddr*)&address, &available) &&
                available == sizeof(address),
            "actual control port identity");
    uint32_t port = address.nl_pid;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    uint64_t before = now(CLOCK_MONOTONIC), real_before = now(CLOCK_REALTIME);
    require(sendto(fd, bytes, size, 0, (struct sockaddr*)&kernel, sizeof(kernel)) == (ssize_t)size,
            "complete address or route request");
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    require(poll(&ready, 1, 5000) == 1 && (ready.revents & POLLIN),
            "bounded control acknowledgement");
    _Alignas(8) unsigned char response[512];
    available = sizeof(kernel);
    ssize_t length =
        recvfrom(fd, response, sizeof(response), 0, (struct sockaddr*)&kernel, &available);
    require(length >= 36 && available == sizeof(kernel) && !kernel.nl_pid && !kernel.nl_groups,
            "kernel acknowledgement ownership");
    const struct nlmsghdr* reply = (const void*)response;
    require(reply->nlmsg_len == (unsigned)length && reply->nlmsg_type == NLMSG_ERROR &&
                reply->nlmsg_seq == sequence && reply->nlmsg_pid == port,
            "matching complete acknowledgement");
    int result;
    memcpy(&result, response + 16, 4);
    uint64_t after = now(CLOCK_MONOTONIC), real_after = now(CLOCK_REALTIME);
    printf("LIFETIME_WIRE_CONTROL {\"case\":%u,\"before_ns\":%llu,\"after_ns\":%llu,"
           "\"realtime_before_ns\":%llu,\"realtime_after_ns\":%llu,\"request\":\"",
           current_case, (unsigned long long)before, (unsigned long long)after,
           (unsigned long long)real_before, (unsigned long long)real_after);
    hex(bytes, size);
    printf("\",\"reply\":\"");
    hex(response, (size_t)length);
    puts("\"}");
    require(!close(fd), "close control description");
    return result;
}

static void address(uint32_t value, int remove, int replace, uint32_t valid) {
    _Alignas(8) unsigned char bytes[80] = {0};
    struct nlmsghdr* message = (void*)bytes;
    message->nlmsg_type = remove ? RTM_DELADDR : RTM_NEWADDR;
    message->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
                           (remove    ? 0
                            : replace ? NLM_F_REPLACE
                                      : NLM_F_CREATE | NLM_F_EXCL);
    struct ifaddrmsg body = {.ifa_family = AF_INET, .ifa_prefixlen = 24, .ifa_index = device};
    memcpy(bytes + 16, &body, sizeof(body));
    uint32_t network = htonl(value);
    size_t size = attribute(bytes, 24, IFA_LOCAL, &network, 4);
    size = attribute(bytes, size, IFA_ADDRESS, &network, 4);
    if (!remove) {
        struct ifa_cacheinfo cache = {
            .ifa_prefered = valid, .ifa_valid = valid, .cstamp = 0x12345678, .tstamp = 0x87654321};
        size = attribute(bytes, size, IFA_CACHEINFO, &cache, sizeof(cache));
    }
    require(!submit(bytes, size), "address mutation");
}

static void route(void) {
    _Alignas(8) unsigned char bytes[64] = {0};
    struct nlmsghdr* message = (void*)bytes;
    message->nlmsg_type = RTM_NEWROUTE;
    message->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    struct rtmsg body = {.rtm_family = AF_INET,
                         .rtm_dst_len = 32,
                         .rtm_table = RT_TABLE_MAIN,
                         .rtm_protocol = RTPROT_BOOT,
                         .rtm_scope = RT_SCOPE_LINK,
                         .rtm_type = RTN_UNICAST};
    memcpy(bytes + 16, &body, sizeof(body));
    uint32_t network = htonl(peer), metric = 10;
    size_t size = attribute(bytes, 28, RTA_DST, &network, 4);
    size = attribute(bytes, size, RTA_OIF, &device, 4);
    size = attribute(bytes, size, RTA_PRIORITY, &metric, 4);
    require(!submit(bytes, size), "owned direct route");
}

static int assigned(uint32_t value) {
    _Static_assert(sizeof(struct ifreq) == 40, "Linux x86-64 interface inventory");
    struct ifreq entries[96] = {0};
    struct ifconf query = {.ifc_len = sizeof(entries), .ifc_buf = (char*)entries};
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0 && !ioctl(fd, SIOCGIFCONF, &query) && query.ifc_len >= 0 &&
                (unsigned)query.ifc_len <= sizeof(entries) && !(query.ifc_len % sizeof(entries[0])),
            "complete actual address inventory");
    uint64_t monotonic = now(CLOCK_MONOTONIC), realtime = now(CLOCK_REALTIME);
    printf(
        "LIFETIME_WIRE_IFCONF {\"case\":%u,\"monotonic_ns\":%llu,\"realtime_ns\":%llu,\"bytes\":\"",
        current_case, (unsigned long long)monotonic, (unsigned long long)realtime);
    hex(entries, (size_t)query.ifc_len);
    puts("\"}");
    int found = 0;
    for (size_t at = 0; at < (size_t)query.ifc_len / sizeof(entries[0]); at++) {
        const struct sockaddr_in* address = (const void*)&entries[at].ifr_addr;
        found |= address->sin_family == AF_INET && ntohl(address->sin_addr.s_addr) == value;
    }
    require(!close(fd), "close inventory description");
    return found;
}

static int policy(const char* scope, int write_value, int value) {
    char path[128], bytes[32];
    require(snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/promote_secondaries", scope) >
                0,
            "policy path");
    int fd = open(path, write_value ? O_WRONLY : O_RDONLY);
    require(fd >= 0, "policy description");
    if (write_value) {
        int size = snprintf(bytes, sizeof(bytes), "%d\n", value);
        require(write(fd, bytes, (size_t)size) == size, "promotion policy write");
    } else {
        ssize_t size = read(fd, bytes, sizeof(bytes) - 1);
        require(size > 0, "promotion policy read");
        bytes[size] = 0;
        value = atoi(bytes);
    }
    require(!close(fd), "close policy description");
    event(write_value ? "policy-write" : "policy-read", value);
    return value;
}

static void command(unsigned char expected) {
    unsigned char received;
    require(read(STDIN_FILENO, &received, 1) == 1 && received == expected,
            "owned peer barrier byte");
    event("command", received);
}

static void payload(unsigned char* bytes, unsigned tag) {
    for (unsigned at = 0; at < 64; at++)
        bytes[at] = (unsigned char)(current_case * 29 + tag * 71 + at * 17 + 11);
    memcpy(bytes, "AXLIFE01", 8);
    bytes[8] = (unsigned char)current_case;
    bytes[9] = (unsigned char)tag;
}

static struct sockaddr_in endpoint(uint32_t value, unsigned port) {
    struct sockaddr_in result = {.sin_family = AF_INET,
                                 .sin_port = htons((uint16_t)port),
                                 .sin_addr = {.s_addr = htonl(value)}};
    return result;
}

static int bound_socket(int type, unsigned protocol, unsigned port) {
    int fd = socket(AF_INET, type | SOCK_CLOEXEC, (int)protocol);
    require(fd >= 0 &&
                !setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1),
            "bound transport description");
    struct sockaddr_in source = endpoint(local, port);
    require(!bind(fd, (struct sockaddr*)&source, sizeof(source)), "assigned source binding");
    return fd;
}

static void guard_exchange(int fd, unsigned tag) {
    unsigned char bytes[64], reply[256];
    payload(bytes, tag);
    struct sockaddr_in target = endpoint(guard, 0);
    require(sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&target, sizeof(target)) ==
                sizeof(bytes),
            "guard packet accepted");
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    require(poll(&ready, 1, 5000) == 1 && (ready.revents & POLLIN),
            "guard reply physical deadline");
    uint64_t before = now(CLOCK_MONOTONIC), real_before = now(CLOCK_REALTIME);
    ssize_t size = recv(fd, reply, sizeof(reply), 0);
    require(size >= 20, "complete guard reply header");
    received(tag, reply, (size_t)size, before, real_before);
    size_t header = (reply[0] & 15) * 4u;
    require(size >= 84 && header >= 20 && header + 64 == (size_t)size && reply[9] == 254 &&
                !memcmp(reply + header, bytes, sizeof(bytes)),
            "exact guard reply bytes");
    event(tag == 1 ? "guard-before" : "guard-after", size);
}

static void wait_until(uint64_t deadline) {
    for (;;) {
        uint64_t current = now(CLOCK_MONOTONIC);
        if (current >= deadline)
            return;
        uint64_t left = deadline - current;
        struct timespec delay = {(time_t)(left / 1000000000), (long)(left % 1000000000)};
        require(!nanosleep(&delay, NULL) || errno == EINTR, "actual address lifetime interval");
    }
}

static void stream_record(int fd, unsigned tag) {
    unsigned char bytes[64], reply[64];
    payload(bytes, tag);
    require(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "complete stream write");
    size_t used = 0;
    uint64_t deadline = now(CLOCK_MONOTONIC) + 5000000000;
    while (used < sizeof(reply)) {
        uint64_t current = now(CLOCK_MONOTONIC);
        require(current < deadline, "stream reply physical deadline");
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        int milliseconds = (int)((deadline - current + 999999) / 1000000);
        require(poll(&ready, 1, milliseconds) == 1 && (ready.revents & POLLIN),
                "stream reply readiness");
        uint64_t before = now(CLOCK_MONOTONIC), real_before = now(CLOCK_REALTIME);
        ssize_t size = recv(fd, reply + used, sizeof(reply) - used, 0);
        require(size > 0, "stream reply prefix");
        received(tag, reply + used, (size_t)size, before, real_before);
        used += (size_t)size;
    }
    require(!memcmp(bytes, reply, sizeof(reply)), "exact stream guard record");
}

static void exercise(void) {
    peer = (local & 0xffffff00) | (16 + current_case % 12);
    event("begin", 0);
    command('S');
    policy(interface, 1, survival == 3);
    uint32_t other = survival == 1 ? local + 256 : local + 1;
    address(local, 0, 0, UINT32_MAX);
    if (survival)
        address(other, 0, 0, UINT32_MAX);
    route();
    int guard_fd = bound_socket(SOCK_RAW, 254, 0);
    guard_exchange(guard_fd, 1);
    int fd = bound_socket(transport == 2   ? SOCK_STREAM
                          : transport == 1 ? SOCK_RAW
                                           : SOCK_DGRAM,
                          transport == 1 ? 253 : 0, transport == 1 ? 0 : 39000 + 2 * current_case);
    struct sockaddr_in target = endpoint(peer, 44732);
    if (transport == 2) {
        struct timeval timeout = {.tv_sec = 5};
        require(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
                "finite stream connect bound");
        require(!connect(fd, (struct sockaddr*)&target, sizeof(target)), "established peer stream");
        stream_record(fd, 4);
        event("stream-before", 64);
    }
    address(local, 0, 1, 1);
    uint64_t began = now(CLOCK_MONOTONIC);
    event("lifetime-start", 1);
    unsigned char bytes[64];
    payload(bytes, transport == 2 ? 5 : 2);
    if (transport != 2) {
        require(sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&target, sizeof(target)) ==
                    sizeof(bytes),
                "copied datagram admitted before expiry");
        memset(bytes, 0xcc, sizeof(bytes));
        event("queued", 64);
    }
    wait_until(began + 1500000000);
    uint64_t expiry_deadline = began + 2500000000;
    while (assigned(local)) {
        uint64_t current = now(CLOCK_MONOTONIC);
        require(current < expiry_deadline, "bounded actual primary expiry");
        uint64_t next = current + 50000000;
        wait_until(next < expiry_deadline ? next : expiry_deadline);
    }
    require(now(CLOCK_MONOTONIC) <= expiry_deadline, "bounded actual primary withdrawal");
    event("withdrawn", 0);
    require(assigned(other) == (survival == 1 || survival == 3),
            "actual cascade or surviving address");
    command('B');
    int fresh = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in source = endpoint(local, 0);
    errno = 0;
    require(fresh >= 0 && bind(fresh, (struct sockaddr*)&source, sizeof(source)) == -1 &&
                errno == EADDRNOTAVAIL,
            "fresh binding rejects expired source");
    event("fresh-bind", -errno);
    require(!close(fresh), "close rejected binding");
    if (transport == 2) {
        require(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes),
                "transport owns bytes while source is absent");
        memset(bytes, 0xcc, sizeof(bytes));
        event("expired", 64);
        uint64_t start = now(CLOCK_MONOTONIC), deadline = start + 2000000000;
        for (;;) {
            uint64_t current = now(CLOCK_MONOTONIC);
            if (current >= deadline)
                break;
            struct pollfd ready = {.fd = fd, .events = POLLIN};
            int result = poll(&ready, 1, (int)((deadline - current + 999999) / 1000000));
            require(!result || (result == -1 && errno == EINTR),
                    "no obsolete stream delivery while source is absent");
        }
        require(now(CLOCK_MONOTONIC) - start >= 2000000000, "unchanged stream absence observation");
        event("absence-end", 0);
    } else {
        errno = 0;
        require(sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&target, sizeof(target)) ==
                        -1 &&
                    errno == ENETUNREACH,
                "later output rejects expired source");
        event("expired", -errno);
    }
    command('R');
    address(local, 0, 0, UINT32_MAX);
    event("restored", 0);
    if (transport == 2) {
        unsigned char expected[64], reply[64];
        payload(expected, 5);
        size_t used = 0;
        uint64_t deadline = now(CLOCK_MONOTONIC) + 5000000000;
        while (used < sizeof(reply)) {
            uint64_t current = now(CLOCK_MONOTONIC);
            require(current < deadline, "restored stream deadline");
            struct pollfd ready = {.fd = fd, .events = POLLIN};
            require(poll(&ready, 1, (int)((deadline - current + 999999) / 1000000)) == 1 &&
                        (ready.revents & POLLIN),
                    "restored stream readiness");
            uint64_t before = now(CLOCK_MONOTONIC), real_before = now(CLOCK_REALTIME);
            ssize_t size = recv(fd, reply + used, sizeof(reply) - used, 0);
            require(size > 0, "restored stream prefix");
            received(5, reply + used, (size_t)size, before, real_before);
            used += (size_t)size;
        }
        require(!memcmp(expected, reply, sizeof(reply)),
                "original copied stream bytes recover exactly");
        event("stream-after", used);
    }
    require(!close(fd), "transport close");
    guard_exchange(guard_fd, 3);
    require(!close(guard_fd), "guard close");
    address(local, 1, 0, 0);
    if (assigned(other))
        address(other, 1, 0, 0);
    event("end", 0);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    require(argc == 3, "two explicit interface names");
    if (isatty(STDIN_FILENO)) {
        struct termios terminal;
        require(!tcgetattr(STDIN_FILENO, &terminal), "console command attributes");
        cfmakeraw(&terminal);
        require(!tcsetattr(STDIN_FILENO, TCSANOW, &terminal), "single-byte console commands");
    }
    const char* barrier = getenv("LIFETIME_WIRE_RUNTIME_FD");
    if (barrier) {
        puts("LIFETIME_WIRE_RUNTIME_READY");
        unsigned char released;
        require(read(atoi(barrier), &released, 1) == 1 && released == 0xa5 && !close(atoi(barrier)),
                "captured native runtime release");
    }
    int original_all = policy("all", 0, 0);
    policy("all", 1, 0);
    for (lane = 0; lane < 2; lane++) {
        interface = argv[lane + 1];
        device = if_nametoindex(interface);
        require(device, "actual selected interface index");
        local = 0xc6124002 + lane * 0x1000;
        peer = local - 1;
        guard = (local & 0xffffff00) | 254;
        int original_device = policy(interface, 0, 0);
        for (transport = 0; transport < 3; transport++)
            for (survival = 0; survival < 4; survival++, current_case++)
                exercise();
        policy(interface, 1, original_device);
    }
    policy("all", 1, original_all);
    puts("LIFETIME_WIRE_PASS cases=24 interfaces=2 transports=3 survival_states=4");
    return 0;
}
