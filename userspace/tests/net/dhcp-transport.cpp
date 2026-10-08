// SPDX-License-Identifier: GPL-3.0-or-later
// Exercises production modules; normal daemon startup remains a separate gate.
#include "net/dhcp/transport.hpp"
#include "net/config/configuration.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

using namespace ax::dhcp;

static void check(bool condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "DHCP_TRANSPORT_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static uint64_t milliseconds() {
    timespec now;
    check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return uint64_t(now.tv_sec) * 1000 + uint64_t(now.tv_nsec) / 1000000;
}

struct Installation {
    const Interface& interface;
    ax::net::Store runtime{"/run/dhcp-transport-owned"};
    ax::net::Configuration configuration;
    Lease installed;

    Installation(const Interface& selected) : interface(selected) {
        check(configuration.open(interface, runtime) == 0,
              "production configuration ownership and recovery");
    }

    void verify_routes(bool present) {
        ax::net::Routing observer;
        ax::net::Route routes[64];
        size_t count = 0;
        check(observer.open() == 0 && observer.list(routes, 64, count, interface.index, 16) == 0 &&
                  count == size_t(present),
              "independently observed owned route count");
        if (present)
            check(!routes[0].destination && !routes[0].mask &&
                      routes[0].gateway == installed.parameters.router &&
                      routes[0].metric == 1000 + interface.index && !routes[0].scope,
                  "actual configured default route matches the accepted ACK");
    }

    void apply(const Lease& lease, unsigned generation) {
        uint32_t observed = 0, mask = 0;
        check(query_address(interface.name, observed, mask) == 0 && observed == installed.address,
              "unconfigured fixture or previously owned address");
        uint32_t expected = 0x0a170028 + (interface.index << 8);
        check(lease.address == expected &&
                  lease.parameters.mask == (generation == 1 ? 0xffffff00u : 0xffffff80u) &&
                  lease.parameters.dns_count == 1 &&
                  lease.parameters.dns[0] == (expected & 0xffffff00) + (generation == 1 ? 53 : 54),
              "ACK configuration independently differs from its offer and prior lease");
        check(configuration.apply(lease.address, lease.parameters, 1000 + interface.index) == 0,
              "production configuration commits accepted lease");
        installed = lease;
        check(query_address(interface.name, observed, mask) == 0 && observed == installed.address &&
                  mask == installed.parameters.mask,
              "actual complete address tuple matches the accepted ACK");
        verify_routes(true);
    }

    void remove() {
        check(configuration.withdraw() == 0, "production configuration withdraws ownership");
        verify_routes(false);
        char path[128];
        snprintf(path, sizeof(path), "/run/dhcp-transport-owned/%s.owned", interface.name);
        check(access(path, F_OK) < 0 && errno == ENOENT,
              "withdrawal removes its synchronized ownership journal");
        installed = {};
        printf("DHCP_TRANSPORT_OWNERSHIP_PASS index=%u\n", interface.index);
    }
};

static void exercise(unsigned index) {
    Interface interface;
    check(query_interface(index, interface) == 0, "selected Ethernet identity");
    uint32_t address = 0, mask = 0;
    check(query_address(interface.name, address, mask) == 0 && !address,
          "fixture begins without another owner's IPv4 configuration");
    Transport transport;
    check(transport.open(interface) == 0, "raw bootstrap and wildcard UDP sockets");
    Installation installation(interface);
    ax::net::Store store("/tmp/dhcp-transport-hints");
    Client client(interface.identity);
    unsigned installs = 0, renewals = 0, rebindings = 0;
    bool stopped = false;
    Event event;
    event.input = Input::start;
    uint64_t start = milliseconds();
    Action action = client.advance(event, start, 0);
    for (;;) {
        uint64_t now = milliseconds();
        check(now < start + 50000, "isolated acquisition/renewal deadline");
        for (unsigned work = 0; action.operation != Operation::none && work < 16; work++) {
            bool success = true;
            if (action.operation == Operation::install) {
                installs++;
                installation.apply(action.lease, installs);
                check(transport.configured(action.lease.address) == 0,
                      "specific UDP binding after address installation");
                check(store.write_hint(interface.name, interface.identity, action.lease.address) ==
                          0,
                      "saved owned lease hint");
                printf("DHCP_TRANSPORT_BOUND index=%u generation=%u\n", index, installs);
            } else if (action.operation == Operation::withdraw) {
                check(transport.configured(0) == 0, "close configured UDP binding");
                installation.remove();
            } else if (action.operation == Operation::forget)
                check(store.forget_hint(interface.name) == 0, "revoke saved hint");
            else {
                int error = transport.transmit(action);
                check(!error || error == EAGAIN, "owned packet output");
                success = !error;
                if (success && action.operation == Operation::transmit) {
                    renewals += action.request.mode == Mode::renew;
                    rebindings += action.request.mode == Mode::rebind;
                }
            }
            event = {};
            event.input = Input::completion;
            event.token = action.token;
            event.success = success;
            action = client.advance(event, milliseconds(), 0);
        }
        if (installs == 2 && !stopped && client.configured()) {
            stopped = true;
            event = {};
            event.input = Input::stop;
            action = client.advance(event, milliseconds(), 0);
            continue;
        }
        if (stopped && client.phase() == Phase::stopped && !client.configured() &&
            action.operation == Operation::none) {
            check(installs == 2 && renewals == 1 && rebindings == 1,
                  "complete raw acquisition and UDP renewal/rebinding path");
            check(query_address(interface.name, address, mask) == 0 && !address,
                  "teardown leaves no isolated address");
            printf("DHCP_TRANSPORT_PASS index=%u renewals=%u rebindings=%u\n", index, renewals,
                   rebindings);
            return;
        }
        if (action.operation != Operation::none)
            continue;
        for (unsigned work = 0; work < 32; work++) {
            Reply reply;
            Received received;
            bool probing = client.phase() == Phase::probing || client.phase() == Phase::installing;
            check(transport.receive(client.transaction(), client.conflict_address(), probing, reply,
                                    received) == 0,
                  "owned raw/UDP ingress");
            if (received == Received::empty)
                break;
            if (received == Received::ignored)
                continue;
            event = {};
            event.input = received == Received::conflict ? Input::conflict : Input::reply;
            event.reply = &reply;
            action = client.advance(event, milliseconds(), 0);
            if (action.operation != Operation::none)
                break;
        }
        if (action.operation == Operation::none) {
            now = milliseconds();
            action = client.advance({}, now, 0);
            if (action.operation == Operation::none) {
                pollfd descriptors[3];
                size_t count = transport.descriptors(descriptors, 3);
                uint64_t due = client.deadline();
                int timeout = due <= now ? 0 : due - now < 100 ? int(due - now) : 100;
                check(poll(descriptors, count, timeout) >= 0, "bounded event loop readiness");
            }
        }
    }
}

int main() {
    puts("DHCP_TRANSPORT_READY");
    fflush(stdout);
    setvbuf(stdout, nullptr, _IOLBF, 0);
    exercise(1);
    exercise(2);
    puts("DHCP_TRANSPORT_TESTS_PASS");
}
