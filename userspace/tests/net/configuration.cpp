// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "net/config/configuration.hpp"
#include "net/dhcp/transport.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ax;
static dhcp::Interface interfaces[2];

static void check(bool condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "CONFIGURATION_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static uint32_t address(unsigned lane, unsigned host = 40) {
    return 0x0a170100 + (lane << 8) + host;
}

static uint32_t ioctl_address(unsigned lane, unsigned code, uint32_t value = 0) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "independent address observer socket");
    ifreq request{};
    memcpy(request.ifr_name, interfaces[lane].name, 16);
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(value);
    memcpy(&request.ifr_addr, &endpoint, sizeof(endpoint));
    int result = ioctl(fd, code, &request), error = errno;
    check(close(fd) == 0 && (result == 0 || (code == SIOCGIFADDR && error == EADDRNOTAVAIL)),
          "independent address ioctl completes");
    if (result < 0)
        return 0;
    memcpy(&endpoint, &request.ifr_addr, sizeof(endpoint));
    return ntohl(endpoint.sin_addr.s_addr);
}

static void verify_address(unsigned lane, uint32_t expected, uint32_t mask = 0) {
    check(ioctl_address(lane, SIOCGIFADDR) == expected, "exact observed local address");
    if (expected)
        check(ioctl_address(lane, SIOCGIFNETMASK) == mask &&
                  ioctl_address(lane, SIOCGIFBRDADDR) == (~mask < 2 ? 0 : expected | ~mask),
              "exact observed prefix and broadcast");
}

struct Message {
    uint8_t bytes[128]{};
    nlmsghdr header{};
    ifaddrmsg body{};
    size_t size = 24;

    Message(unsigned lane, bool remove) {
        static uint32_t sequence = 100;
        header.nlmsg_type = remove ? RTM_DELADDR : RTM_NEWADDR;
        header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_EXCL);
        header.nlmsg_seq = ++sequence;
        header.nlmsg_pid = 0x76543210;
        body.ifa_family = AF_INET;
        body.ifa_prefixlen = 25;
        body.ifa_flags = IFA_F_PERMANENT;
        body.ifa_index = interfaces[lane].index;
        attribute(IFA_LOCAL, htonl(address(lane)));
        attribute(IFA_ADDRESS, htonl(address(lane)));
        attribute(IFA_BROADCAST, htonl(address(lane, 127)));
    }

    void attribute(unsigned type, uint32_t value) {
        rtattr field{};
        field.rta_len = 8;
        field.rta_type = type;
        memcpy(bytes + size, &field, 4);
        memcpy(bytes + size + 4, &value, 4);
        size += 8;
    }

    void finish() {
        header.nlmsg_len = size;
        memcpy(bytes, &header, 16);
        memcpy(bytes + 16, &body, 8);
    }
};

static void receipt(int fd, const Message& message, int expected) {
    uint8_t reply[128];
    sockaddr_nl source{}, local{};
    socklen_t length = sizeof(source), local_length = sizeof(local);
    check(recvfrom(fd, reply, sizeof(reply), 0, reinterpret_cast<sockaddr*>(&source), &length) ==
                  36 &&
              length == sizeof(source) && source.nl_family == AF_NETLINK && !source.nl_pid &&
              !source.nl_groups &&
              getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_length) == 0,
          "independent capped address reply and authoritative kernel sender");
    nlmsghdr header, echo;
    int result;
    memcpy(&header, reply, 16);
    memcpy(&result, reply + 16, 4);
    memcpy(&echo, reply + 20, 16);
    check(header.nlmsg_len == 36 && header.nlmsg_type == NLMSG_ERROR &&
              header.nlmsg_flags == NLM_F_CAPPED && header.nlmsg_seq == message.header.nlmsg_seq &&
              header.nlmsg_pid == local.nl_pid && result == -expected &&
              !memcmp(&echo, &message.header, 16),
          "address ACK preserves original request, sequence, port, and errno");
}

static void exchange(int fd, Message& message, int expected) {
    message.finish();
    check(send(fd, message.bytes, message.size, 0) == ssize_t(message.size),
          "independent address request accepted");
    receipt(fd, message, expected);
}

static void message_contract(bool native) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE), capped = 1;
    check(fd >= 0 && setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &capped, 4) == 0,
          "independent address-message socket");
    for (unsigned lane = 0; lane < 2; lane++) {
        Message create(lane, false);
        exchange(fd, create, 0);
        verify_address(lane, address(lane), 0xffffff80);
        exchange(fd, create, EEXIST);
        Message remove(lane, true);
        remove.body.ifa_prefixlen = 24;
        uint32_t broadcast = htonl(address(lane, 255));
        memcpy(remove.bytes + 44, &broadcast, 4);
        exchange(fd, remove, EADDRNOTAVAIL);
        verify_address(lane, address(lane), 0xffffff80);
        remove = Message(lane, true);
        exchange(fd, remove, 0);
        verify_address(lane, 0);
        exchange(fd, remove, EADDRNOTAVAIL);
        if (!native) {
            for (unsigned kind = 0; kind < 9; kind++) {
                Message invalid(lane, false);
                int expected = EINVAL;
                switch (kind) {
                case 0:
                    invalid.body.ifa_prefixlen = 33;
                    break;
                case 1:
                    invalid.body.ifa_family = AF_INET6;
                    expected = EAFNOSUPPORT;
                    break;
                case 2:
                    invalid.body.ifa_flags |= IFA_F_SECONDARY;
                    expected = EOPNOTSUPP;
                    break;
                case 3:
                    invalid.body.ifa_scope = RT_SCOPE_LINK;
                    expected = EOPNOTSUPP;
                    break;
                case 4:
                    invalid.attribute(IFA_LOCAL, htonl(address(lane)));
                    break;
                case 5:
                    invalid.attribute(IFA_FLAGS, 128);
                    expected = EOPNOTSUPP;
                    break;
                case 6:
                    invalid.bytes[39] ^= 1;
                    break;
                case 7:
                    invalid.header.nlmsg_flags |= NLM_F_REPLACE;
                    expected = EOPNOTSUPP;
                    break;
                case 8:
                    invalid.body.ifa_index = 65535;
                    expected = ENODEV;
                    break;
                }
                exchange(fd, invalid, expected);
                verify_address(lane, 0);
            }
        }
        net::Routing adapter;
        net::Address value{address(lane, 41), 0xffffff00, address(lane, 255),
                           interfaces[lane].index};
        check(adapter.open() == 0 && adapter.change(value, false) == 0,
              "production adapter commits complete tuple");
        verify_address(lane, value.address, value.mask);
        check(adapter.change(value, false) == EEXIST && adapter.change(value, true) == 0,
              "production adapter preserves exclusive-create and exact-delete results");
        verify_address(lane, 0);
    }
    check(close(fd) == 0, "close independent address-message socket");
    puts("CONFIGURATION_ADDRESS_MESSAGES_PASS interfaces=2");
}

static void address_pressure() {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    int capped = 1;
    check(fd >= 0 && setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &capped, 4) == 0,
          "prepare address reply pressure");
    nlmsghdr requests[32];
    for (auto& header : requests) {
        Message missing(0, true);
        missing.finish();
        check(send(fd, missing.bytes, missing.size, 0) == ssize_t(missing.size),
              "fill real reply datagram slots without assigning an address");
        header = missing.header;
    }
    Message install(0, false);
    install.finish();
    pollfd readiness{fd, POLLOUT, 0};
    check(poll(&readiness, 1, 0) == 0 && !(readiness.revents & POLLOUT) &&
              send(fd, install.bytes, install.size, 0) < 0 && errno == EAGAIN,
          "full reply queue rejects address mutation and write readiness");
    verify_address(0, 0);
    Message echoed(0, true);
    echoed.header = requests[0];
    receipt(fd, echoed, EADDRNOTAVAIL);
    readiness.revents = 0;
    check(poll(&readiness, 1, 0) == 1 && (readiness.revents & POLLOUT) &&
              send(fd, install.bytes, install.size, 0) == ssize_t(install.size),
          "released reservation permits the original complete address request");
    verify_address(0, address(0), 0xffffff80);
    for (unsigned i = 1; i < 32; i++) {
        echoed.header = requests[i];
        receipt(fd, echoed, EADDRNOTAVAIL);
    }
    receipt(fd, install, 0);
    Message remove(0, true);
    exchange(fd, remove, 0);
    check(close(fd) == 0, "release address pressure description");
    verify_address(0, 0);
    puts("CONFIGURATION_ADDRESS_PRESSURE_PASS replies=32");
}

static dhcp::Parameters parameters(unsigned lane, uint32_t mask = 0xffffff00) {
    dhcp::Parameters result;
    result.has_mask = true;
    result.mask = mask;
    result.router = address(lane, 1);
    return result;
}

static bool contains(net::Routing& observer, const net::Route& expected) {
    net::Route saved[64];
    size_t count = 0;
    check(observer.list(saved, 64, count) == 0, "independent description inspects actual routes");
    for (size_t i = 0; i < count; i++) {
        const auto& value = saved[i];
        if (value.destination == expected.destination && value.mask == expected.mask &&
            value.gateway == expected.gateway && value.metric == expected.metric &&
            value.index == expected.index && value.protocol == expected.protocol &&
            value.scope == expected.scope)
            return true;
    }
    return false;
}

static size_t owned(net::Routing& observer, unsigned lane, uint8_t protocol = RTPROT_DHCP) {
    net::Route saved[64];
    size_t count = 0;
    check(observer.list(saved, 64, count, interfaces[lane].index, protocol) == 0,
          "inspect owned protocol/interface snapshot");
    return count;
}

static void recovery(const net::Store& runtime) {
    net::Routing observer;
    check(observer.open() == 0, "recovery observer");
    for (unsigned lane = 0; lane < 2; lane++) {
        net::Route foreign{0xcb007100,  0xffffff00,   0, 3001 + lane, interfaces[lane].index,
                           RTPROT_BOOT, RT_SCOPE_LINK};
        net::Configuration owner;
        check(owner.open(interfaces[lane], runtime) == 0, "open configuration owner");
        auto original = parameters(lane);
        check(owner.apply(address(lane), original, 2001 + lane) == 0,
              "install initial configuration");
        check(observer.change(foreign, false) == 0, "unrelated manual route");
        check(owner.apply(address(lane), original, 2001 + lane) == 0 &&
                  owned(observer, lane) == 1 && contains(observer, foreign),
              "configuration installs tagged route and preserves unrelated manual route");
        verify_address(lane, address(lane), original.mask);
        auto changed = parameters(lane, 0xffffff80);
        changed.route_count = 1;
        changed.routes[0] = {0xc6336400, 0xffffff00, 0};
        check(owner.apply(address(lane, 41), changed, 2001 + lane) == 0 &&
                  owned(observer, lane) == 2 && contains(observer, foreign) &&
                  owner.apply(address(lane, 41), changed, 2001 + lane) == 0,
              "replacement and unchanged renewal retain exact ownership");
        verify_address(lane, address(lane, 41), changed.mask);
        owner.close(); // A stopped process leaves the synchronized journal.
        net::Configuration restarted;
        check(restarted.open(interfaces[lane], runtime) == 0 && !owned(observer, lane) &&
                  contains(observer, foreign) && restarted.withdraw() == 0,
              "restart removes recorded owned routes while retaining manual route");
        verify_address(lane, 0);
        check(restarted.apply(address(lane, 80), original, 0, RTPROT_STATIC) == 0 &&
                  owned(observer, lane, RTPROT_STATIC) == 1 && restarted.withdraw() == 0,
              "static-profile routes have their own checked protocol and automatic priority");
        check(observer.change(foreign, true) == 0, "release manual fixture route");
        verify_address(lane, 0);
    }
    puts("CONFIGURATION_REPLACEMENT_RECOVERY_PASS interfaces=2");
}

static void manual_preservation(const net::Store& runtime) {
    net::Routing observer;
    check(observer.open() == 0, "manual-configuration observer");
    for (unsigned lane = 0; lane < 2; lane++) {
        net::Configuration owner;
        auto lease = parameters(lane);
        check(owner.open(interfaces[lane], runtime) == 0 && owner.apply(address(lane), lease) == 0,
              "prepare owned address before manual intervention");
        ioctl_address(lane, SIOCSIFADDR, address(lane, 77));
        owner.close();
        net::Configuration restarted;
        check(restarted.open(interfaces[lane], runtime) == 0 && !owned(observer, lane) &&
                  restarted.apply(address(lane), lease) == EBUSY && restarted.withdraw() == 0,
              "restart and failed acquisition preserve a manually changed address");
        verify_address(lane, address(lane, 77), lease.mask);
        ioctl_address(lane, SIOCSIFADDR, 0);
    }
    puts("CONFIGURATION_MANUAL_PRESERVATION_PASS interfaces=2");
}

static void write_file(const char* path, const void* data, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    check(fd >= 0 && write(fd, data, size) == ssize_t(size) && fsync(fd) == 0 && close(fd) == 0,
          "publish controlled journal corruption fixture");
}

static size_t read_file(const char* path, uint8_t* bytes, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t size = fd < 0 ? -1 : read(fd, bytes, capacity);
    check(size >= 60 && size < ssize_t(capacity) && close(fd) == 0,
          "read actual synchronized ownership journal");
    return size;
}

static void journal_word(uint8_t* bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        bytes[i] = value >> (i * 8);
}

static void journal_checksum(uint8_t* bytes, size_t size) {
    uint32_t checksum = 2166136261;
    for (size_t i = 16; i < size; i++)
        checksum = (checksum ^ bytes[i]) * 16777619;
    journal_word(bytes + 12, checksum);
}

static void corrupt_journal(const net::Store& runtime, const char* directory) {
    net::Routing observer;
    check(observer.open() == 0, "corrupt-journal observer");
    net::Configuration owner;
    auto lease = parameters(0);
    check(owner.open(interfaces[0], runtime) == 0 && owner.apply(address(0), lease) == 0,
          "prepare synchronized ownership record");
    owner.close();
    char path[300];
    snprintf(path, sizeof(path), "%s/%s.owned", directory, interfaces[0].name);
    uint8_t original[4096];
    size_t size = read_file(path, original, sizeof(original));
    uint8_t corrupt[4096];
    memcpy(corrupt, original, size);
    corrupt[size - 1] ^= 1;
    write_file(path, corrupt, size);
    for (unsigned i = 0; i < 70; i++) {
        net::Configuration rejected;
        check(rejected.open(interfaces[0], runtime) == EINVAL &&
                  rejected.apply(address(0), lease) == EBADF && owned(observer, 0) == 1,
              "corrupt ownership record changes no state and releases failed-open descriptors");
    }
    verify_address(0, address(0), lease.mask);
    write_file(path, original, 19);
    net::Configuration truncated;
    check(truncated.open(interfaces[0], runtime) == EINVAL && owned(observer, 0) == 1,
          "truncated journal cannot claim ownership");
    check(size == 84, "single-route record has documented size");
    for (unsigned kind = 0; kind < 8; kind++) {
        memcpy(corrupt, original, size);
        int expected = EINVAL;
        switch (kind) {
        case 0:
            journal_word(corrupt + 16, 99);
            expected = ESTALE;
            break;
        case 1:
            corrupt[20] ^= 2;
            expected = ESTALE;
            break;
        case 2:
            journal_word(corrupt + 56, UINT32_MAX);
            break;
        case 3:
            journal_word(corrupt + 48, 0xfffeffff);
            break;
        case 4:
            corrupt[80] = RTPROT_BOOT;
            break;
        case 5:
            journal_word(corrupt + 72, 0);
            break;
        case 6:
            corrupt[26] = 1;
            break;
        case 7:
            journal_word(corrupt + 52, address(0, 254));
            break;
        }
        journal_checksum(corrupt, size);
        write_file(path, corrupt, size);
        net::Configuration rejected;
        check(rejected.open(interfaces[0], runtime) == expected && owned(observer, 0) == 1,
              "valid checksum cannot bypass ownership identity and semantic validation");
        verify_address(0, address(0), lease.mask);
    }
    write_file(path, original, size);
    net::Configuration recovered;
    check(recovered.open(interfaces[0], runtime) == 0 && !owned(observer, 0),
          "restored valid record cleans the original owned state");
    verify_address(0, 0);
    puts("CONFIGURATION_CORRUPT_JOURNAL_PASS cycles=70 semantic=8");
}

static void journal_failure(const net::Store& runtime, const char* directory) {
    net::Routing observer;
    net::Configuration owner;
    check(observer.open() == 0 && owner.open(interfaces[0], runtime) == 0,
          "prepare actual journal-publication failure");
    char path[300];
    snprintf(path, sizeof(path), "%s/%s.owned", directory, interfaces[0].name);
    check(mkdir(path, 0700) == 0, "directory blocks atomic journal rename");
    check(owner.apply(address(0), parameters(0)) == EISDIR && !owned(observer, 0),
          "failed intent publication installs no route");
    verify_address(0, 0);
    check(rmdir(path) == 0 && owner.apply(address(0), parameters(0)) == 0,
          "retry repairs pending cleanup after publication failure");
    verify_address(0, address(0), 0xffffff00);
    check(owner.withdraw() == 0 && !owned(observer, 0), "release successfully retried ownership");
    verify_address(0, 0);
    puts("CONFIGURATION_JOURNAL_FAILURE_PASS");
}

static void partial_recovery(const net::Store& runtime, const char* directory) {
    constexpr unsigned lane = 1, metric = 2002;
    char path[300];
    snprintf(path, sizeof(path), "%s/%s.owned", directory, interfaces[lane].name);
    auto before = parameters(lane), after = parameters(lane, 0xffffff80);
    after.route_count = 1;
    after.routes[0] = {0xc6336400, 0xffffff00, 0};
    net::Configuration owner;
    uint8_t old_record[4096], new_record[4096], intent[132];
    check(owner.open(interfaces[lane], runtime) == 0 &&
              owner.apply(address(lane), before, metric) == 0,
          "capture production journal before replacement");
    size_t old_size = read_file(path, old_record, sizeof(old_record));
    check(owner.apply(address(lane, 41), after, metric) == 0,
          "capture production journal after replacement");
    size_t new_size = read_file(path, new_record, sizeof(new_record));
    check(old_size == 84 && new_size == 108 && owner.withdraw() == 0,
          "documented snapshots contain one old and two new routes");
    owner.close();
    // Derive an interrupted intent from production-written snapshots. Each
    // child leaves a real kernel state at one replacement stage and exits.
    memcpy(intent, new_record, 60);
    journal_word(intent + 8, sizeof(intent));
    memcpy(intent + 28, old_record + 44, 16);
    memcpy(intent + 60, old_record + 60, 24);
    memcpy(intent + 84, new_record + 60, 48);
    journal_checksum(intent, sizeof(intent));
    net::Route gateway{
        0, 0, address(lane, 1), metric, interfaces[lane].index, RTPROT_DHCP, RT_SCOPE_UNIVERSE};
    net::Route onlink{0xc6336400,  0xffffff00,   0, metric, interfaces[lane].index,
                      RTPROT_DHCP, RT_SCOPE_LINK};
    net::Route foreign{0xcb007100,  0xffffff00,   0, 3002, interfaces[lane].index,
                       RTPROT_BOOT, RT_SCOPE_LINK};
    net::Address old_address{address(lane), before.mask, address(lane, 255),
                             interfaces[lane].index};
    net::Address new_address{address(lane, 41), after.mask, address(lane, 127),
                             interfaces[lane].index};
    net::Routing observer;
    check(observer.open() == 0, "partial-replacement observer");
    for (unsigned phase = 0; phase < 6; phase++) {
        pid_t child = fork();
        check(child >= 0, "fork partially replaced owner");
        if (!child) {
            net::Routing writer;
            check(writer.open() == 0 && writer.change(old_address, false) == 0 &&
                      writer.change(gateway, false) == 0 && writer.change(foreign, false) == 0,
                  "prepare recorded old and independent manual state");
            write_file(path, intent, sizeof(intent));
            if (phase >= 1)
                check(writer.change(gateway, true) == 0, "old route removed before process exit");
            if (phase >= 2)
                check(writer.change(old_address, true) == 0,
                      "old address removed before process exit");
            if (phase >= 3)
                check(writer.change(new_address, false) == 0,
                      "new address installed before process exit");
            if (phase >= 4)
                check(writer.change(onlink, false) == 0,
                      "first new route installed before process exit");
            if (phase >= 5)
                check(writer.change(gateway, false) == 0,
                      "all new routes installed before process exit");
            _exit(0);
        }
        int status;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
              "actual owner exits at a recorded replacement boundary");
        verify_address(lane,
                       phase < 2    ? old_address.address
                       : phase == 2 ? 0
                                    : new_address.address,
                       phase < 2 ? before.mask : after.mask);
        check(owned(observer, lane) == (phase == 0  ? 1u
                                        : phase < 4 ? 0u
                                                    : phase - 3),
              "independent observer confirms each partial route state");
        net::Configuration restarted;
        check(restarted.open(interfaces[lane], runtime) == 0 && !owned(observer, lane) &&
                  contains(observer, foreign),
              "intent recovery clears either owned tuple and retains the unrelated route");
        verify_address(lane, 0);
        check(observer.change(foreign, true) == 0, "release manual boundary fixture route");
    }
    puts("CONFIGURATION_INTENT_RECOVERY_PASS phases=6");
}

static void process_recovery(const net::Store& runtime) {
    pid_t child = fork();
    check(child >= 0, "fork configuration owner");
    if (!child) {
        net::Configuration owner;
        check(owner.open(interfaces[1], runtime) == 0 &&
                  owner.apply(address(1), parameters(1)) == 0,
              "child publishes owned configuration");
        _exit(0); // Exercise kernel process teardown, without a C++ destructor.
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "child exits with live owned configuration");
    verify_address(1, address(1), 0xffffff00);
    net::Configuration restarted;
    check(restarted.open(interfaces[1], runtime) == 0, "recover after actual process exit");
    verify_address(1, 0);
    puts("CONFIGURATION_PROCESS_RECOVERY_PASS");
}

static void rollback(const net::Store& runtime) {
    net::Configuration owner;
    net::Routing observer;
    auto original = parameters(0);
    check(observer.open() == 0 && owner.open(interfaces[0], runtime) == 0 &&
              owner.apply(address(0), original, 4001) == 0,
          "prepare rollback configuration");
    net::Route manual[31];
    for (unsigned i = 0; i < 31; i++) {
        manual[i] = {0x64400000 + (i << 8), 0xffffff00,   0, 5000 + i, interfaces[0].index,
                     RTPROT_BOOT,           RT_SCOPE_LINK};
        check(observer.change(manual[i], false) == 0, "fill actual kernel route slots");
    }
    auto changed = parameters(0, 0xffffff80);
    changed.route_count = 1;
    changed.routes[0] = {0xc6336400, 0xffffff00, 0};
    check(owner.apply(address(0, 41), changed, 4001) == ENOBUFS && owned(observer, 0) == 1,
          "failed second route installation rolls back complete earlier owned configuration");
    verify_address(0, address(0), original.mask);
    for (const auto& value : manual)
        check(contains(observer, value), "rollback preserves each unrelated route");
    check(owner.withdraw() == 0, "withdraw restored configuration");
    for (const auto& value : manual)
        check(observer.change(value, true) == 0, "release isolated route-capacity fixture");
    verify_address(0, 0);
    puts("CONFIGURATION_ROLLBACK_PASS manual_routes=31");
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    bool native = argc == 2 && !strcmp(argv[1], "--native");
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        check(dhcp::query_interface(if_nametoindex(name), interfaces[lane]) == 0,
              "two physical Ethernet interfaces");
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ifreq request{};
        memcpy(request.ifr_name, name, sizeof(request.ifr_name));
        check(fd >= 0 && ioctl(fd, SIOCGIFFLAGS, &request) == 0, "read fixture administration");
        request.ifr_flags |= IFF_UP;
        check(ioctl(fd, SIOCSIFFLAGS, &request) == 0 && close(fd) == 0,
              "enable fixture interface without changing carrier");
        verify_address(lane, 0);
    }
    message_contract(native);
    if (!native) {
        address_pressure();
        char directory[100];
        snprintf(directory, sizeof(directory), "/tmp/axiom64-network-owner-%ld", long(getpid()));
        net::Store runtime(directory);
        recovery(runtime);
        manual_preservation(runtime);
        corrupt_journal(runtime, directory);
        journal_failure(runtime, directory);
        partial_recovery(runtime, directory);
        process_recovery(runtime);
        rollback(runtime);
    }
    puts("CONFIGURATION_TESTS_PASS");
}
