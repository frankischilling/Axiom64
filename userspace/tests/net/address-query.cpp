// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/dhcp/transport.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __GLIBC__
using IoctlRequest = unsigned long;
#else
using IoctlRequest = int;
#endif
extern "C" int __real_ioctl(int, IoctlRequest, ...);

enum class Boundary { idle, remove_after_address, fail_address, fail_mask };
static Boundary boundary = Boundary::idle;
static bool removed;
static unsigned observed;

static void check(bool value, const char* reason) {
    if (!value) {
        fprintf(stderr, "ADDRESS_QUERY_FAIL reason=%s errno=%d\n", reason, errno);
        exit(1);
    }
}

static void withdraw(int descriptor, const char* name) {
    ifreq request{};
    memcpy(request.ifr_name, name, strlen(name) + 1);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    memcpy(&request.ifr_addr, &address, sizeof(address));
    check(__real_ioctl(descriptor, SIOCSIFADDR, &request) == 0,
          "actual private IPv4 address is removed");
}

extern "C" int __wrap_ioctl(int descriptor, IoctlRequest operation, ...) {
    va_list arguments;
    va_start(arguments, operation);
    void* argument = va_arg(arguments, void*);
    va_end(arguments);
    if ((boundary == Boundary::fail_address && operation == SIOCGIFADDR) ||
        (boundary == Boundary::fail_mask && operation == SIOCGIFNETMASK)) {
        errno = EIO;
        return -1;
    }
    int result = __real_ioctl(descriptor, operation, argument);
    int error = result < 0 ? errno : 0;
    if (boundary == Boundary::remove_after_address) {
        observed++;
        printf("ADDRESS_QUERY_IOCTL operation=%#lx result=%d error=%d\n",
               static_cast<unsigned long>(operation), result, error);
        if (!result && operation == SIOCGIFADDR) {
            withdraw(descriptor, static_cast<ifreq*>(argument)->ifr_name);
            removed = true;
            puts("ADDRESS_QUERY_ACTUAL_WITHDRAW result=0");
        }
    }
    errno = error;
    return result;
}

static void configure(const char* name) {
    int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    check(descriptor >= 0, "actual control socket");
    ifreq request{};
    check(strlen(name) < IFNAMSIZ, "bounded interface name");
    memcpy(request.ifr_name, name, strlen(name) + 1);
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(0x0a170128);
    memcpy(&request.ifr_addr, &endpoint, sizeof(endpoint));
    check(ioctl(descriptor, SIOCSIFADDR, &request) == 0, "actual private address configured");
    endpoint.sin_addr.s_addr = htonl(0xffffff00);
    memcpy(&request.ifr_netmask, &endpoint, sizeof(endpoint));
    check(ioctl(descriptor, SIOCSIFNETMASK, &request) == 0 &&
              ioctl(descriptor, SIOCGIFFLAGS, &request) == 0,
          "actual private mask and flags");
    request.ifr_flags |= IFF_UP;
    check(ioctl(descriptor, SIOCSIFFLAGS, &request) == 0 && close(descriptor) == 0,
          "actual private device remains up");
}

static unsigned descriptors() {
    unsigned count = 0;
    for (int descriptor = 0; descriptor < 64; descriptor++)
        count += fcntl(descriptor, F_GETFD) >= 0;
    return count;
}

static void exercise(const char* name) {
    unsigned before = descriptors();
    configure(name);
    uint32_t address = 0, mask = 0;
    check(ax::dhcp::query_address(name, address, mask) == 0 && address == 0x0a170128 &&
              mask == 0xffffff00,
          "actual ordinary complete tuple");
    boundary = Boundary::remove_after_address;
    removed = false;
    observed = 0;
    address = 0xa5a5a5a5;
    mask = 0x5a5a5a5a;
    int result = ax::dhcp::query_address(name, address, mask);
    boundary = Boundary::idle;
    printf("ADDRESS_QUERY_BOUNDARY interface=%s result=%d address=%08x mask=%08x removed=%d "
           "reads=%u\n",
           name, result, address, mask, removed, observed);
    check(result == 0 && !address && !mask && removed && observed == 2,
          "actual concurrent withdrawal returns an empty complete tuple");
    check(ax::dhcp::query_address(name, address, mask) == 0 && !address && !mask,
          "already absent address is the same empty tuple");
    const Boundary failures[]{Boundary::fail_address, Boundary::fail_mask};
    for (Boundary injected : failures) {
        configure(name);
        boundary = injected;
        address = 0xa5a5a5a5;
        mask = 0x5a5a5a5a;
        result = ax::dhcp::query_address(name, address, mask);
        boundary = Boundary::idle;
        check(result == EIO && address == 0xa5a5a5a5 && mask == 0x5a5a5a5a,
              "other syscall errors preserve both caller outputs");
    }
    int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    check(descriptor >= 0, "cleanup control socket");
    withdraw(descriptor, name);
    check(close(descriptor) == 0 && descriptors() == before,
          "actual query descriptors are closed on every path");
    printf("ADDRESS_QUERY_PASS interface=%s actual_withdrawal=1 no_leaked_descriptors=1 "
           "real_errors_preserved=1\n",
           name);
}

int main(int argc, char** argv) {
    setbuf(stdout, nullptr);
    check(argc == 3, "two actual isolated interface names");
    for (int index = 1; index < argc; index++)
        exercise(argv[index]);
    return 0;
}
