// SPDX-License-Identifier: GPL-3.0-or-later
#define main network_fixture_main
#ifdef IPV4_CONTROL_MODEL
#include "ipv4.c"
#else
#include "udp.c"
#endif
#undef main
#include <stdarg.h>

static unsigned calls;
static unsigned short observed;

int __wrap_ioctl(int fd, unsigned long command, ...) {
    check(fd == 17 && calls < 2, "only actual administrative control ioctls");
    va_list arguments;
    va_start(arguments, command);
    struct ifreq* request = va_arg(arguments, struct ifreq*);
    va_end(arguments);
    if (!calls++) {
        check(command == SIOCSIFFLAGS && !(request->ifr_flags & IFF_UP),
              "actual administrative shutdown requested");
    } else {
        check(command == SIOCGIFFLAGS, "actual administrative flag readback requested");
        request->ifr_flags = observed;
    }
    return 0;
}

int main(int argc, char** argv) {
    check(argc == 2, "one administrative flag observation");
    observed = strtoul(argv[1], NULL, 16);
    struct ifreq request = {.ifr_flags = IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST};
    strcpy(request.ifr_name, "eth0");
    administrative_down(17, &request, 0);
    check(calls == 2 && request.ifr_flags == observed, "both actual control operations completed");
    return 0;
}
