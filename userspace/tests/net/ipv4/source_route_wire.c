// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static unsigned current_case, started, observed;
static int control_fd, raw_fd;
static int after_clock;
static int synchronized_clock;
static int alias_active;
static unsigned raw_seen, sample_mask;
static int raw_drained;
static uint64_t empty_before_ns, guard_deadline_ns;
static int guard_completed;
static unsigned char packet[65536];

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "IPV4_SOURCE_WIRE_FAIL case=%u operation=%s errno=%d\n", current_case,
                operation, errno);
        exit(1);
    }
}

static void emit(const char* format, ...) {
    char text[512];
    va_list arguments;
    va_start(arguments, format);
    int size = vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    require(size > 0 && (size_t)size < sizeof(text), "bounded-record");
    require(write(STDOUT_FILENO, text, (size_t)size) == size, "complete-record");
}

#include "source_route_apps.h"

static void integer(const char* name, int value) {
    char path[160], text[32];
    int size = snprintf(path, sizeof(path), "/proc/sys/net/ipv4/%s", name);
    require(size > 0 && (size_t)size < sizeof(path), "control-path");
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    require(fd >= 0, "control-open");
    size = snprintf(text, sizeof(text), "%d\n", value);
    require(write(fd, text, (size_t)size) == size && close(fd) == 0, "control-write");
}

static struct ifreq interface(unsigned index) {
    struct ifreq result = {0};
    require(index < 2, "interface-index");
    snprintf(result.ifr_name, sizeof(result.ifr_name), "eth%u", index);
    return result;
}

static void administrative(unsigned index, int up) {
    struct ifreq request = interface(index);
    require(ioctl(control_fd, SIOCGIFFLAGS, &request) == 0, "read-link-flags");
    if (up)
        request.ifr_flags |= IFF_UP;
    else
        request.ifr_flags &= ~IFF_UP;
    require(ioctl(control_fd, SIOCSIFFLAGS, &request) == 0, "write-link-flags");
}

static void address(unsigned index, uint32_t value) {
    struct ifreq request = interface(index);
    struct sockaddr_in* selected = (struct sockaddr_in*)&request.ifr_addr;
    selected->sin_family = AF_INET;
    selected->sin_addr.s_addr = htonl(value);
    require(ioctl(control_fd, SIOCSIFADDR, &request) == 0, "interface-address");
    if (value) {
        selected->sin_addr.s_addr = htonl(0xffffff00);
        require(ioctl(control_fd, SIOCSIFNETMASK, &request) == 0, "interface-mask");
    }
}

static void alias_address(uint32_t value) {
    struct ifreq request = interface(1);
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth1:keep");
    struct sockaddr_in* selected = (struct sockaddr_in*)&request.ifr_addr;
    selected->sin_family = AF_INET;
    selected->sin_addr.s_addr = htonl(value);
    require(ioctl(control_fd, SIOCSIFADDR, &request) == 0, "egress-alias-address");
    if (value) {
        selected->sin_addr.s_addr = htonl(0xffffff00);
        require(ioctl(control_fd, SIOCSIFNETMASK, &request) == 0, "egress-alias-mask");
    }
    alias_active = value != 0;
}

static void alias_query(const char* phase) {
    struct ifreq request = interface(1);
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth1:keep");
    require(ioctl(control_fd, SIOCGIFADDR, &request) == 0, "surviving-egress-alias");
    struct sockaddr_in* selected = (struct sockaddr_in*)&request.ifr_addr;
    require(selected->sin_family == AF_INET && ntohl(selected->sin_addr.s_addr) == 0x0a020001,
            "retained-egress-alias-address");
    emit("IPV4_SOURCE_ALIAS case=%u phase=%s address=%08x\n", current_case, phase,
         ntohl(selected->sin_addr.s_addr));
}

static void mtu(unsigned index, int value) {
    struct ifreq request = interface(index);
    request.ifr_mtu = value;
    require(ioctl(control_fd, SIOCSIFMTU, &request) == 0, "interface-mtu");
}

static void route(uint32_t target, uint32_t gateway, int remove, int absent_okay) {
    struct rtentry request = {0};
    struct sockaddr_in* destination = (struct sockaddr_in*)&request.rt_dst;
    struct sockaddr_in* mask = (struct sockaddr_in*)&request.rt_genmask;
    struct sockaddr_in* via = (struct sockaddr_in*)&request.rt_gateway;
    destination->sin_family = mask->sin_family = via->sin_family = AF_INET;
    destination->sin_addr.s_addr = htonl(target);
    mask->sin_addr.s_addr = htonl(0xffffff00);
    via->sin_addr.s_addr = htonl(gateway);
    request.rt_dev = "eth1";
    request.rt_flags = RTF_UP | (gateway ? RTF_GATEWAY : 0);
    int result = ioctl(control_fd, remove ? SIOCDELRT : SIOCADDRT, &request);
    require(!result || (remove && absent_okay && (errno == ESRCH || errno == ENOENT)),
            "route-change");
}

static void source_clock(const char* prefix, const char* phase) {
    struct timespec before, realtime, after;
    require(clock_gettime(CLOCK_MONOTONIC, &before) == 0 &&
                clock_gettime(CLOCK_REALTIME, &realtime) == 0 &&
                clock_gettime(CLOCK_MONOTONIC, &after) == 0,
            "actual-source-clocks");
    emit("%s case=%u phase=%s realtime_ns=%llu monotonic_before_ns=%llu "
         "monotonic_after_ns=%llu\n",
         prefix, current_case, phase,
         (unsigned long long)((uint64_t)realtime.tv_sec * 1000000000 + realtime.tv_nsec),
         (unsigned long long)((uint64_t)before.tv_sec * 1000000000 + before.tv_nsec),
         (unsigned long long)((uint64_t)after.tv_sec * 1000000000 + after.tv_nsec));
}

static void clock_record(const char* phase) {
    source_clock("IPV4_SOURCE_WIRE_CLOCK", phase);
}

static void raw_clock(unsigned packet_number, int polled) {
    struct timespec before, realtime, after;
    require(clock_gettime(CLOCK_MONOTONIC, &before) == 0 &&
                clock_gettime(CLOCK_REALTIME, &realtime) == 0 &&
                clock_gettime(CLOCK_MONOTONIC, &after) == 0,
            "actual-raw-source-clocks");
    emit("IPV4_SOURCE_RAW_CLOCK case=%u packet=%u mode=%s realtime_ns=%llu "
         "monotonic_before_ns=%llu monotonic_after_ns=%llu empty_before_ns=%llu\n",
         current_case, packet_number, polled ? "poll" : "command",
         (unsigned long long)((uint64_t)realtime.tv_sec * 1000000000 + realtime.tv_nsec),
         (unsigned long long)((uint64_t)before.tv_sec * 1000000000 + before.tv_nsec),
         (unsigned long long)((uint64_t)after.tv_sec * 1000000000 + after.tv_nsec),
         (unsigned long long)empty_before_ns);
}

static void change_egress_property(const char* action) {
    int mask = !strcmp(action, "egress-mask");
    struct ifreq request = interface(1);
    struct sockaddr_in* selected = (struct sockaddr_in*)&request.ifr_addr;
    selected->sin_family = AF_INET;
    selected->sin_addr.s_addr = htonl(mask ? 0xffffffff : 0x0a01007f);
    require(ioctl(control_fd, mask ? SIOCSIFNETMASK : SIOCSIFBRDADDR, &request) == 0,
            "egress-property-change");
    request = interface(1);
    require(ioctl(control_fd, SIOCGIFADDR, &request) == 0 &&
                ((struct sockaddr_in*)&request.ifr_addr)->sin_addr.s_addr == htonl(0x0a010001),
            "egress-source-retained");
    request = interface(1);
    require(ioctl(control_fd, mask ? SIOCGIFNETMASK : SIOCGIFBRDADDR, &request) == 0,
            "egress-property-query");
    uint32_t value = ntohl(((struct sockaddr_in*)&request.ifr_addr)->sin_addr.s_addr);
    require(value == (mask ? 0xffffffff : 0x0a01007f), "egress-property-retained");
    emit("IPV4_SOURCE_ADDRESS case=%u action=%s address=0a010001 value=%08x\n", current_case,
         action, value);
}

static void begin(unsigned id, int maximum, int all_source, int link_source, int forwarding,
                  int link_forwarding) {
    require(id == started && observed == started && maximum >= 68 && maximum <= 1500,
            "ordered-case");
    require(application_fd == -1 && accepted_fd == -1, "previous-application-closed");
    current_case = id;
    if (alias_active)
        alias_address(0);
    unsigned char byte;
    errno = 0;
    require(recv(raw_fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT) == -1 &&
                (errno == EAGAIN || errno == EWOULDBLOCK),
            "previous-raw-queue-empty");
    for (unsigned index = 0; index < 2; index++)
        administrative(index, 0);
    for (unsigned index = 0; index < 2; index++) {
        address(index, index ? 0x0a010001 : 0x0a000001);
        mtu(index, index ? maximum : 1500);
        administrative(index, 1);
    }
    route(0xcb007100, 0x0a010002, 1, 1);
    route(0xcb007100, 0x0a010002, 0, 0);
    integer("conf/all/accept_source_route", all_source);
    integer("conf/lo/accept_source_route", 1);
    integer("conf/eth0/accept_source_route", link_source);
    integer("conf/eth1/accept_source_route", 1);
    integer("ip_forward", 1);
    integer("ip_forward", forwarding);
    integer("conf/eth0/forwarding", link_forwarding);
    started++;
    after_clock = 0;
    synchronized_clock = 0;
    raw_seen = sample_mask = 0;
    raw_drained = 0;
    empty_before_ns = guard_deadline_ns = 0;
    guard_completed = 0;
    clock_record("before");
    emit("IPV4_SOURCE_WIRE_READY case=%u\n", id);
}

static void mutate(const char* action) {
    require(started == observed + 1, "active-mutation");
    if (!strcmp(action, "egress-address")) {
        address(1, 0);
        if (alias_active)
            alias_query("survived");
    } else if (!strcmp(action, "egress-mask") || !strcmp(action, "egress-broadcast"))
        change_egress_property(action);
    else if (!strcmp(action, "ingress-address"))
        address(0, 0);
    else if (!strcmp(action, "route"))
        route(0x0a010000, 0, 1, 0);
    else if (!strcmp(action, "mtu") || !strcmp(action, "mtu-df"))
        mtu(1, 576);
    else if (!strcmp(action, "down") || !strcmp(action, "flap")) {
        administrative(1, 0);
        if (!strcmp(action, "flap"))
            administrative(1, 1);
    } else if (!strcmp(action, "forwarding"))
        integer("conf/eth0/forwarding", 0);
    else if (!strcmp(action, "source-policy"))
        integer("conf/all/accept_source_route", 0);
    else
        require(!strcmp(action, "baseline"), "known-mutation");
    emit("IPV4_SOURCE_WIRE_MUTATED case=%u action=%s\n", current_case, action);
}

static void drain_raw(unsigned id, int polled) {
    require(id == current_case && started == observed + 1, "active-observation");
    for (;;) {
        struct sockaddr_in source = {0};
        socklen_t available = sizeof(source);
        ssize_t size = recvfrom(raw_fd, packet, sizeof(packet), MSG_DONTWAIT | MSG_TRUNC,
                                (struct sockaddr*)&source, &available);
        if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        require(size >= 20 && size <= 65535 && available == sizeof(source) &&
                    source.sin_family == AF_INET && !source.sin_port,
                "raw-datagram");
        raw_clock(raw_seen, polled);
        emit("IPV4_SOURCE_WIRE_RAW case=%u packet=%u bytes=%ld source=%08x\n", id, raw_seen,
             (long)size, ntohl(source.sin_addr.s_addr));
        for (size_t offset = 0; offset < (size_t)size; offset += 64) {
            char text[129];
            size_t length = (size_t)size - offset;
            if (length > 64)
                length = 64;
            for (size_t at = 0; at < length; at++) {
                text[2 * at] = "0123456789abcdef"[packet[offset + at] >> 4];
                text[2 * at + 1] = "0123456789abcdef"[packet[offset + at] & 15];
            }
            text[2 * length] = 0;
            emit("IPV4_SOURCE_WIRE_RAW_BYTES case=%u packet=%u offset=%zu data=%s\n", id, raw_seen,
                 offset, text);
        }
        raw_seen++;
    }
}

static void observe(unsigned id) {
    require(!sample_mask || (sample_mask == 7 && raw_drained), "complete-delayed-source-samples");
    drain_raw(id, 0);
    observed++;
    emit("IPV4_SOURCE_WIRE_OBSERVED case=%u packets=%u\n", id, raw_seen);
}

static char* read_command(char* line, size_t capacity) {
    size_t used = 0;
    for (;;) {
        struct pollfd descriptors[2] = {{STDIN_FILENO, POLLIN, 0}, {raw_fd, POLLIN, 0}};
        struct timespec before;
        require(clock_gettime(CLOCK_MONOTONIC, &before) == 0, "actual-poll-source-clock");
        uint64_t now = (uint64_t)before.tv_sec * 1000000000 + before.tv_nsec;
        require(!guard_deadline_ns || now <= guard_deadline_ns, "raw-error-guard-arm-timeout");
        int ready = poll(descriptors, 2, guard_deadline_ns ? 0 : 10);
        if (ready < 0 && errno == EINTR)
            continue;
        require(ready >= 0 && !(descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)),
                "command-and-raw-poll");
        if (descriptors[1].revents & POLLIN)
            drain_raw(current_case, 1);
        else
            // A pre-poll clock stays a lower bound if the observer is descheduled.
            empty_before_ns = (uint64_t)before.tv_sec * 1000000000 + before.tv_nsec;
        require(!(descriptors[0].revents & (POLLERR | POLLNVAL)), "command-input-poll");
        if (descriptors[0].revents & (POLLIN | POLLHUP)) {
            char byte;
            ssize_t size = read(STDIN_FILENO, &byte, 1);
            if (size < 0 && errno == EINTR)
                continue;
            require(size >= 0 && used + 1 < capacity, "bounded-command-input");
            if (!size) {
                require(!used, "complete-command-input");
                return NULL;
            }
            // A guard must not wait for another UART tick to complete a line.
            if (byte == '!' && !used) {
                line[0] = '!';
                line[1] = 0;
                return line;
            }
            line[used++] = byte;
            if (byte == '\n') {
                line[used] = 0;
                return line;
            }
        }
    }
}

int main(int argc, char** argv) {
    require(argc == 2 && geteuid() == 0, "privileged-invocation");
    char* end;
    unsigned long total = strtoul(argv[1], &end, 10);
    require(!*end && total > 0 && total <= 1000, "case-count");
    struct utsname kernel;
    require(uname(&kernel) == 0, "kernel-identity");
    if (!strcmp(kernel.sysname, "Linux")) {
        const char* parent = getenv("IPV4_SOURCE_PARENT_NETNS");
        const char* barrier = getenv("IPV4_SOURCE_RUNTIME_FD");
        struct stat own;
        unsigned char release;
        require(parent && stat("/proc/self/ns/net", &own) == 0 &&
                    own.st_ino != (ino_t)strtoull(parent, NULL, 10),
                "private-native-network");
        require(barrier && read(atoi(barrier), &release, 1) == 1 && release == 0xa5 &&
                    close(atoi(barrier)) == 0,
                "captured-native-runtime");
    } else
        require(!strcmp(kernel.sysname, "Axiom64"), "supported-kernel");
    if (isatty(STDIN_FILENO)) {
        struct termios terminal;
        require(tcgetattr(STDIN_FILENO, &terminal) == 0, "console-state");
        cfmakeraw(&terminal);
        require(tcsetattr(STDIN_FILENO, TCSANOW, &terminal) == 0, "console-commands");
    }
    control_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    raw_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    require(control_fd >= 0 && raw_fd >= 0 &&
                setsockopt(raw_fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5) == 0,
            "network-descriptions");
    emit("IPV4_SOURCE_WIRE_KERNEL version=2 sysname=%s release=%s cases=%lu\n", kernel.sysname,
         kernel.release, total);
    char line[256];
    while (read_command(line, sizeof(line))) {
        unsigned id, port;
        int maximum, all_source, link_source, forwarding, link_forwarding;
        char action[32], extra;
        if (sscanf(line, "case %u %d %d %d %d %d %c", &id, &maximum, &all_source, &link_source,
                   &forwarding, &link_forwarding, &extra) == 6) {
            require(started < total, "bounded-case");
            begin(id, maximum, all_source, link_source, forwarding, link_forwarding);
        } else if (sscanf(line, "alias %u %c", &id, &extra) == 1) {
            require(id == current_case && started == observed + 1 && !alias_active,
                    "one-active-egress-alias");
            alias_address(0x0a020001);
            alias_query("prepared");
        } else if (sscanf(line, "app-open %u %31s %u %c", &id, action, &port, &extra) == 3) {
            require(id == current_case && started == observed + 1, "active-application-open");
            application_open(action, port);
        } else if (sscanf(line, "app-%31s %u %c", action, &id, &extra) == 2) {
            require(id == current_case && started == observed + 1, "active-application-action");
            if (!strcmp(action, "accept"))
                application_accept();
            else if (!strcmp(action, "receive"))
                application_receive();
            else {
                require(!strcmp(action, "close"), "known-application-action");
                application_close();
            }
        } else if (sscanf(line, "mutate %u %31s %c", &id, action, &extra) == 2) {
            require(id == current_case, "mutation-identity");
            mutate(action);
        } else if (sscanf(line, "clock %u %c", &id, &extra) == 1) {
            require(id == current_case && started == observed + 1 && !after_clock,
                    "one-active-clock-observation");
            clock_record("after");
            after_clock = 1;
        } else if (sscanf(line, "sync %u %c", &id, &extra) == 1) {
            require(id == current_case && started == observed + 1 && !synchronized_clock,
                    "one-active-source-synchronization");
            source_clock("IPV4_SOURCE_SYNC", "input");
            synchronized_clock = 1;
        } else if (sscanf(line, "guard-arm %u %c", &id, &extra) == 1) {
            struct timespec now;
            require(id == current_case && started == observed + 1 && !guard_deadline_ns &&
                        !guard_completed && raw_seen == 1 &&
                        clock_gettime(CLOCK_MONOTONIC, &now) == 0,
                    "raw-error-guard-arm");
            guard_deadline_ns = (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec + 2000000000;
            emit("IPV4_SOURCE_GUARD_ARM case=%u\n", id);
        } else if (!strcmp(line, "!")) {
            id = current_case;
            struct pollfd descriptor = {raw_fd, POLLIN, 0};
            // Command receipt follows the host timer boundary. Neither prior
            // consumption nor a queued error can establish an empty guard.
            require(started == observed + 1 && guard_deadline_ns && !guard_completed &&
                        raw_seen == 1 && poll(&descriptor, 1, 0) == 0 && !descriptor.revents,
                    "raw-error-guard-empty");
            guard_deadline_ns = 0;
            guard_completed = 1;
            emit("IPV4_SOURCE_GUARD case=%u packets=%u revents=%d\n", id, raw_seen,
                 descriptor.revents);
        } else if (sscanf(line, "sample %u %31s %c", &id, action, &extra) == 2) {
            require(id == current_case && started == observed + 1 &&
                        ((!strcmp(action, "early") && !sample_mask) ||
                         (!strcmp(action, "late-before") && sample_mask == 1 && raw_drained) ||
                         (!strcmp(action, "late-after") && sample_mask == 3)),
                    "ordered-delayed-source-sample");
            source_clock("IPV4_SOURCE_SAMPLE", action);
            sample_mask = (sample_mask << 1) | 1;
        } else if (sscanf(line, "drain %u %c", &id, &extra) == 1) {
            require(id == current_case && started == observed + 1 && sample_mask == 1 &&
                        !raw_drained,
                    "one-early-raw-drain");
            drain_raw(id, 0);
            raw_drained = 1;
            emit("IPV4_SOURCE_DRAINED case=%u packets=%u\n", id, raw_seen);
        } else if (sscanf(line, "observe %u %c", &id, &extra) == 1)
            observe(id);
        else {
            require(!strcmp(line, "finish\n") && started == total && observed == total,
                    "complete-command-sequence");
            require(application_fd == -1 && accepted_fd == -1,
                    "all-application-descriptions-closed");
            require(close(raw_fd) == 0 && close(control_fd) == 0, "close-descriptions");
            emit("IPV4_SOURCE_WIRE_PASS cases=%lu\n", total);
            return 0;
        }
    }
    require(0, "unexpected-command-eof");
    return 1;
}
