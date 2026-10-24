// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_DEVICE"
#include "ipv6_fixture.h"
#include <fcntl.h>
#include "ipv6_dad_inventory.h"

// The healthy companion carries observations about the selected interface.
// No control packet requires transmission through an unavailable adapter.
enum operation { HELLO, BEGIN, ADDRESS, SUMMARY, ARM, CHANGE, LINK, SECRET, END, FINISH, READY };

static unsigned phases[2], action;
static int control_fd;

static void pause_poll(void) {
    struct timespec delay = {0, 20000000};
    check(!nanosleep(&delay, NULL), "device observation polling");
}

static void emit_control_record(const unsigned char frame[60], uint64_t stamp) {
    char target[33], line[256];
    static const char hex[] = "0123456789abcdef";
    for (unsigned at = 0; at < 16; at++) {
        target[at * 2] = hex[frame[36 + at] >> 4];
        target[at * 2 + 1] = hex[frame[36 + at] & 15];
    }
    target[32] = 0;
    uint32_t fields[3];
    memcpy(fields, frame + 24, sizeof(fields));
    int size =
        snprintf(line, sizeof(line),
                 "IPV6_DEVICE_CONTROL lane=%u phase=%u kind=%u action=%u subject=%u stage=%u "
                 "flags=%x preferred=%u valid=%u target=%s observed_ns=%llu\n",
                 frame[18], frame[19], frame[20], frame[21], frame[22], frame[23], ntohl(fields[0]),
                 ntohl(fields[1]), ntohl(fields[2]), target, (unsigned long long)stamp);
    check(size > 0 && (size_t)size < sizeof(line) && write(STDOUT_FILENO, line, size) == size,
          "complete device query record");
}

static void control(unsigned subject, unsigned kind, unsigned stage,
                    const struct address_record* value) {
    unsigned lane = 1 - subject, phase = phases[lane]++;
    check(phase < 255, "bounded device controls");
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = 0x88;
    frame[13] = 0xc4;
    memcpy(frame + 14, "IP6V", 4);
    frame[18] = lane;
    frame[19] = phase;
    frame[20] = kind;
    frame[21] = action;
    frame[22] = subject;
    frame[23] = stage;
    if (value) {
        uint32_t fields[] = {htonl(value->flags), htonl(value->preferred), htonl(value->valid)};
        memcpy(frame + 24, fields, sizeof(fields));
        memcpy(frame + 36, &value->address, 16);
    }
    uint64_t stamp = now();
    for (unsigned at = 0; at < 8; at++)
        frame[52 + at] = stamp >> (56 - at * 8);
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(0x88c4),
                                 .sll_ifindex = indices[lane],
                                 .sll_halen = 6};
    memcpy(target.sll_addr, frame, 6);
    int observation = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(0x88c4));
    check(observation >= 0, "fresh companion observation socket");
    struct sockaddr_ll binding = {
        .sll_family = AF_PACKET, .sll_protocol = htons(0x88c4), .sll_ifindex = indices[lane]};
    check(!bind(observation, (struct sockaddr*)&binding, sizeof(binding)),
          "fresh companion observation binding");
    check(sendto(observation, frame, sizeof(frame), 0, (struct sockaddr*)&target, sizeof(target)) ==
              sizeof(frame),
          "complete companion device control");
    for (;;) {
        unsigned char reply[1600];
        struct pollfd item = {.fd = observation, .events = POLLIN};
        check(poll(&item, 1, 100) >= 0, "device control readiness");
        ssize_t size = recv(observation, reply, sizeof(reply), MSG_DONTWAIT);
        if (size == 60 && !memcmp(reply, macs[lane], 6) && !memcmp(reply + 6, frame, 6) &&
            !memcmp(reply + 12, frame + 12, 8) && reply[20] == 1 &&
            !memcmp(reply + 21, (unsigned char[39]){0}, 39))
            break;
        check(now() - stamp < 10000000000ULL, "finite device control");
    }
    check(!close(observation), "close companion observation");
    emit_control_record(frame, stamp);
}

static void property(const char* scope, const char* name, int value) {
    scalar(scope, name, value);
    char path[160], bytes[32] = {0}, expected[32];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", scope, name);
    snprintf(expected, sizeof(expected), "%d\n", value);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    check(fd >= 0 && read(fd, bytes, sizeof(bytes) - 1) == (ssize_t)strlen(expected) &&
              !strcmp(bytes, expected),
          "actual device property readback");
    close(fd);
    printf("IPV6_DEVICE_PROPERTY scope=%s name=%s value=%d observed_ns=%llu\n", scope, name, value,
           (unsigned long long)now());
}

static void set_secret(const char* scope, const char* text) {
    char path[160];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/stable_secret", scope);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    check(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text),
          "install actual device stable key");
    close(fd);
}

static void secret(unsigned subject, unsigned stage) {
    char path[160], bytes[64] = {0};
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/eth%u/stable_secret", subject);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t size = fd < 0 ? -1 : read(fd, bytes, sizeof(bytes) - 1);
    check(size == 40 && bytes[size - 1] == '\n', "complete actual device stable key");
    close(fd);
    bytes[size - 1] = 0;
    struct address_record value = {0};
    check(inet_pton(AF_INET6, bytes, &value.address) == 1, "parse actual device stable key");
    control(subject, SECRET, stage, &value);
}

static void inventory(unsigned subject, unsigned stage) {
    struct inventory value = snapshot(subject);
    for (unsigned at = 0; at < value.address_count; at++)
        control(subject, ADDRESS, stage, value.addresses + at);
    struct in6_addr link = {0};
    link.s6_addr[0] = 0xfe;
    link.s6_addr[1] = 0x80;
    struct address_record summary = {.flags = value.address_count,
                                     .preferred = routes(&value, link, 64)};
    control(subject, SUMMARY, stage, &summary);
}

static struct address_record wait_ready(unsigned subject) {
    uint64_t began = now();
    for (;;) {
        struct inventory value = snapshot(subject);
        if (value.address_count == 1 && value.addresses[0].flags == 0x880 &&
            IN6_IS_ADDR_LINKLOCAL(&value.addresses[0].address))
            return value.addresses[0];
        check(now() - began < 8000000000ULL, "bounded actual device DAD completion");
        pause_poll();
    }
}

static void link_state(unsigned subject, unsigned stage) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", subject);
    uint64_t began = now();
    for (;;) {
        check(!ioctl(control_fd, SIOCGIFFLAGS, &request), "query actual device flags");
        if ((action != 2 && stage != 3) ||
            !!(request.ifr_flags & IFF_RUNNING) == (stage != 1 && stage != 2))
            break;
        check(now() - began < 2000000000ULL, "actual device carrier state propagates");
        pause_poll();
    }
    struct address_record value = {.flags = (unsigned short)request.ifr_flags};
    check(!ioctl(control_fd, SIOCGIFMTU, &request), "query actual device MTU");
    value.preferred = request.ifr_mtu;
    char path[160];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/eth%u/disable_ipv6", subject);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    value.valid = fd >= 0;
    check(fd >= 0 || errno == ENOENT, "actual IPv6 scope presence");
    if (fd >= 0)
        close(fd);
    control(subject, LINK, stage, &value);
}

static void change(unsigned subject, int up) {
    if (action == 2) {
        control(subject, CHANGE, up, NULL);
        return;
    }
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", subject);
    if (action == 0) {
        check(!ioctl(control_fd, SIOCGIFFLAGS, &request), "query administrative flags");
        if (up)
            request.ifr_flags |= IFF_UP;
        else
            request.ifr_flags &= ~IFF_UP;
        check(!ioctl(control_fd, SIOCSIFFLAGS, &request), "actual administrative transition");
    } else {
        request.ifr_mtu = up ? 1500 : 1279;
        check(!ioctl(control_fd, SIOCSIFMTU, &request), "actual IPv6 MTU transition");
    }
}

static void quiet_window(void) {
    uint64_t began = now();
    while (now() - began < 4100000000ULL)
        pause_poll();
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    check(argc == 3 && !strcmp(argv[1], "--action") &&
              (!strcmp(argv[2], "administrative") || !strcmp(argv[2], "mtu") ||
               !strcmp(argv[2], "carrier")),
          "known device lifecycle action");
    action = !strcmp(argv[2], "administrative") ? 0 : !strcmp(argv[2], "mtu") ? 1 : 2;
    (void)prefix_address;
    scalar("all", "disable_ipv6", 1);
    scalar("default", "disable_ipv6", 1);
    control_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(control_fd >= 0, "device lifecycle control");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(control_fd, SIOCGIFINDEX, &request), "device lifecycle index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(control_fd, SIOCGIFHWADDR, &request), "device lifecycle MAC");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        check(!ioctl(control_fd, SIOCGIFFLAGS, &request), "initial device flags");
        request.ifr_flags |= IFF_UP;
        check(!ioctl(control_fd, SIOCSIFFLAGS, &request), "device lifecycle adapter up");
    }
    set_secret("default", "fd00::100\n");
    const char* names[] = {"addr_gen_mode", "accept_ra",    "autoconf",
                           "dad_transmits", "enhanced_dad", "router_solicitations",
                           "max_addresses"};
    const int values[] = {2, 0, 0, 1, 1, 0, 16};
    for (unsigned at = 0; at < sizeof(values) / sizeof(*values); at++)
        property("default", names[at], values[at]);
    property("default", "disable_ipv6", 0);
    for (unsigned subject = 0; subject < 2; subject++) {
        char scope[16];
        snprintf(scope, sizeof(scope), "eth%u", subject);
        set_secret(scope, subject ? "fd00::11\n" : "fd00::10\n");
        for (unsigned at = 0; at < sizeof(values) / sizeof(*values); at++)
            property(scope, names[at], values[at]);
        control(subject, HELLO, 0, NULL);
        control(subject, BEGIN, 0, NULL);
        property(scope, "disable_ipv6", 0);
        struct address_record ready = wait_ready(subject);
        control(subject, READY, 0, &ready);
        secret(subject, 0);
        link_state(subject, 0);
        inventory(subject, 0);
        control(subject, ARM, 0, NULL);
        change(subject, 0);
        link_state(subject, 1);
        inventory(subject, 1);
        quiet_window();
        link_state(subject, 2);
        inventory(subject, 2);
        control(subject, ARM, 1, NULL);
        change(subject, 1);
        link_state(subject, 3);
        ready = wait_ready(subject);
        control(subject, READY, 3, &ready);
        quiet_window();
        secret(subject, 4);
        link_state(subject, 4);
        inventory(subject, 4);
        control(subject, END, 0, NULL);
        property(scope, "disable_ipv6", 1);
    }
    for (unsigned subject = 0; subject < 2; subject++)
        control(subject, FINISH, 0, NULL);
    close(control_fd);
    printf("IPV6_DEVICE_PASS adapters=2 action=%s state=ready quiet_seconds=4\n", argv[2]);
    return 0;
}
