// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipv6_device_fixture.h"

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
