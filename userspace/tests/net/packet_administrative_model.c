// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise the packet client's actual administrative flag check.
#define main packet_fixture_main
#include "packet.c"
#undef main
#include <stdarg.h>
#include <sys/resource.h>

static unsigned calls;
static unsigned short queried_flags;

int __wrap_ioctl(int fd, unsigned long operation, ...) {
    check(fd == 17 && calls < 3, "model ioctl descriptor and count");
    va_list arguments;
    va_start(arguments, operation);
    struct ifreq* request = va_arg(arguments, struct ifreq*);
    va_end(arguments);
    if (calls == 1) {
        check(operation == SIOCSIFFLAGS && !(request->ifr_flags & IFF_UP),
              "actual client requests administrative shutdown");
    } else {
        check(operation == SIOCGIFFLAGS, "actual client queries flags");
        request->ifr_flags = calls ? queried_flags : 0x1043;
    }
    calls++;
    return 0;
}

int main(int argc, char** argv) {
    struct rlimit limit = {0};
    check(!setrlimit(RLIMIT_CORE, &limit) && argc == 2, "one packet flag model case");
    const char* name = argv[1];
    queried_flags = !strcmp(name, "linux")     ? 0x1002
                    : !strcmp(name, "running") ? 0x1042
                    : !strcmp(name, "up")      ? 0x1003
                    : !strcmp(name, "both")    ? 0x1043
                    : !strcmp(name, "empty")   ? 0
                                               : UINT16_MAX;
    check(queried_flags != UINT16_MAX, "known packet flag model case");
    struct ifreq request = {0};
    administrative_down(17, &request, 1);
    check(calls == 3, "packet client used all three actual ioctl operations");
    puts("PACKET_ADMINISTRATIVE_MODEL_PASS");
    return 0;
}
