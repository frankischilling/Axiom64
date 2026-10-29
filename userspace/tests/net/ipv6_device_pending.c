// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipv6_device_fixture.h"

enum pending_state { PROBING, REGENERATING, RETRYING, EXHAUSTED };

static unsigned state;
static struct in6_addr conflicted[4];
static unsigned conflict_count;
static int unavailable_ready_recorded;

static unsigned selected(const struct inventory* values, int tentative,
                         struct address_record* result) {
    check(conflict_count <= 4, "bounded device conflict context");
    unsigned found = 0;
    for (unsigned at = 0; at < values->address_count; at++) {
        const struct address_record* value = values->addresses + at;
        if (!IN6_IS_ADDR_LINKLOCAL(&value->address) || (value->flags & IFA_F_DADFAILED) ||
            !!(value->flags & IFA_F_TENTATIVE) != tentative)
            continue;
        int excluded = 0;
        for (unsigned old = 0; old < conflict_count; old++)
            excluded |= !memcmp(&value->address, conflicted + old, 16);
        if (excluded)
            continue;
        *result = *value;
        found++;
    }
    check(found <= 1, "one unconflicted device candidate");
    return found;
}

static struct address_record wait_selected(unsigned subject, int tentative) {
    uint64_t began = now();
    for (;;) {
        struct inventory values = snapshot(subject);
        struct address_record value = {0};
        if (selected(&values, tentative, &value)) {
            check(value.flags == (tentative ? 0x8c0u : 0x880u) && value.preferred == UINT32_MAX &&
                      value.valid == UINT32_MAX,
                  "exact current stable device owner");
            return value;
        }
        check(now() - began < 8000000000ULL, "bounded device owner observation");
        pause_poll();
    }
}

static int probe_socket(unsigned subject) {
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    check(fd >= 0, "actual outgoing probe description");
    struct sockaddr_ll local = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = indices[subject]};
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)), "selected actual probe description");
    return fd;
}

static struct address_record observed_probe(unsigned subject, int fd,
                                            const struct in6_addr* expected) {
    uint64_t began = now();
    for (;;) {
        unsigned char frame[1600];
        struct sockaddr_ll sender = {0};
        socklen_t length = sizeof(sender);
        ssize_t count =
            recvfrom(fd, frame, sizeof(frame), MSG_DONTWAIT, (struct sockaddr*)&sender, &length);
        if (count == 86 && sender.sll_pkttype == PACKET_OUTGOING &&
            !memcmp(frame + 6, macs[subject], 6) && frame[12] == 0x86 && frame[13] == 0xdd &&
            frame[20] == 58 && frame[54] == 135 &&
            !memcmp(frame + 22, (unsigned char[16]){0}, 16) &&
            (!expected || !memcmp(frame + 62, expected, 16))) {
            struct inventory values = snapshot(subject);
            struct address_record value = {0};
            check(selected(&values, 1, &value) && !memcmp(&value.address, frame + 62, 16) &&
                      value.flags == 0x8c0,
                  "actual selected probe owns a tentative stable address");
            return value;
        }
        check(count >= 0 || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR,
              "actual outgoing DAD probe observation");
        check(now() - began < 8000000000ULL, "finite actual selected DAD probe");
        pause_poll();
    }
}

static void wait_exhausted(unsigned subject) {
    uint64_t began = now();
    for (;;) {
        struct inventory values = snapshot(subject);
        unsigned failed = 0;
        for (unsigned at = 0; at < values.address_count; at++)
            failed += values.addresses[at].flags == 0x8c8;
        if (values.address_count == 4 && failed == 4)
            return;
        check(now() - began < 8000000000ULL, "complete four-owner device exhaustion");
        pause_poll();
    }
}

// Both the first inventory and the polling loop publish the first ready owner.
// A slow control acknowledgment must not move that observation to a later poll.
static int first_unavailable_ready(const struct inventory* values, struct address_record* value) {
    if (action != 2 || state == EXHAUSTED || unavailable_ready_recorded ||
        !selected(values, 0, value))
        return 0;
    check(value->flags == 0x880 && value->preferred == UINT32_MAX && value->valid == UINT32_MAX,
          "exact first ready device during carrier loss");
    unavailable_ready_recorded = 1;
    return 1;
}

static void pending_inventory(unsigned subject, unsigned stage) {
    struct inventory values = snapshot(subject);
    struct address_record value = {0};
    if (stage == 1 && first_unavailable_ready(&values, &value))
        control(subject, READY, 1, &value);
    publish_inventory(subject, stage, &values);
}

static void unavailable_window(unsigned subject) {
    uint64_t began = now();
    while (now() - began < 4100000000ULL) {
        if (action == 2 && state != EXHAUSTED && !unavailable_ready_recorded) {
            struct inventory values = snapshot(subject);
            struct address_record value = {0};
            if (first_unavailable_ready(&values, &value))
                control(subject, READY, 1, &value);
        }
        pause_poll();
    }
    check(action != 2 || state == EXHAUSTED || unavailable_ready_recorded,
          "first ready device observed during full carrier-loss interval");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char* states[] = {"probing", "regenerating", "retrying", "exhausted"};
    check(argc == 5 && !strcmp(argv[1], "--action") && !strcmp(argv[3], "--state"),
          "explicit pending-device action and state");
    check(!strcmp(argv[2], "administrative") || !strcmp(argv[2], "mtu") ||
              !strcmp(argv[2], "carrier"),
          "known pending-device action");
    action = !strcmp(argv[2], "administrative") ? 0 : !strcmp(argv[2], "mtu") ? 1 : 2;
    for (state = 0; state < 4 && strcmp(argv[4], states[state]); state++) {
    }
    check(state < 4, "known pending-device state");
    (void)prefix_address;
    (void)wait_ready;
    (void)inventory;
    scalar("all", "disable_ipv6", 1);
    scalar("default", "disable_ipv6", 1);
    control_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(control_fd >= 0, "pending-device lifecycle control");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(control_fd, SIOCGIFINDEX, &request), "pending-device index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(control_fd, SIOCGIFHWADDR, &request), "pending-device MAC");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        check(!ioctl(control_fd, SIOCGIFFLAGS, &request), "initial pending-device flags");
        request.ifr_flags |= IFF_UP;
        check(!ioctl(control_fd, SIOCSIFFLAGS, &request), "pending-device adapter up");
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
        conflict_count = 0;
        unavailable_ready_recorded = 0;
        char scope[16];
        snprintf(scope, sizeof(scope), "eth%u", subject);
        set_secret(scope, subject ? "fd00::11\n" : "fd00::10\n");
        for (unsigned at = 0; at < sizeof(values) / sizeof(*values); at++)
            property(scope, names[at], values[at]);
        control(subject, HELLO, 0, NULL);
        control(subject, BEGIN, 0, NULL);
        struct address_record mode = {.flags = state};
        control(subject, STATE, 0, &mode);
        int fd = probe_socket(subject);
        property(scope, "disable_ipv6", 0);
        struct address_record candidate = observed_probe(subject, fd, NULL);
        control(subject, ADDRESS, 10, &candidate);
        if (state != PROBING) {
            unsigned attempts = state == EXHAUSTED ? 4 : 1;
            for (unsigned at = 0; at < attempts; at++) {
                if (at) {
                    candidate = wait_selected(subject, 1);
                    candidate = observed_probe(subject, fd, &candidate.address);
                    control(subject, ADDRESS, 10 + at, &candidate);
                }
                control(subject, CONFLICT, at, &candidate);
                conflicted[conflict_count++] = candidate.address;
            }
            if (state == EXHAUSTED)
                wait_exhausted(subject);
            else {
                candidate = wait_selected(subject, 1);
                control(subject, ADDRESS, 14, &candidate);
                if (state == RETRYING) {
                    candidate = observed_probe(subject, fd, &candidate.address);
                    control(subject, ADDRESS, 15, &candidate);
                }
            }
        }
        check(!close(fd), "close pending-device probe observer");
        secret(subject, 0);
        link_state(subject, 0);
        pending_inventory(subject, 0);
        control(subject, ARM, 0, NULL);
        change(subject, 0);
        link_state(subject, 1);
        pending_inventory(subject, 1);
        unavailable_window(subject);
        link_state(subject, 2);
        pending_inventory(subject, 2);
        control(subject, ARM, 1, NULL);
        change(subject, 1);
        link_state(subject, 3);
        if (action != 2)
            conflict_count = 0;
        if (action != 2 || state != EXHAUSTED) {
            struct address_record ready = wait_selected(subject, 0);
            control(subject, READY, 3, &ready);
        }
        quiet_window();
        secret(subject, 4);
        link_state(subject, 4);
        pending_inventory(subject, 4);
        control(subject, END, 0, NULL);
        property(scope, "disable_ipv6", 1);
    }
    for (unsigned subject = 0; subject < 2; subject++)
        control(subject, FINISH, 0, NULL);
    check(!close(control_fd), "close pending-device lifecycle control");
    printf("IPV6_DEVICE_PASS adapters=2 action=%s state=%s quiet_seconds=4\n", argv[2],
           states[state]);
    return 0;
}
