// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/administrative_flags_model.c
 * @brief   Interface administrative flag model.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Provides modeled flag transitions for tests of interface control behavior.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
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
