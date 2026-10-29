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
    if (result != -expected)
        fprintf(stderr, "CONFIGURATION_ACK_MISMATCH sequence=%u type=%u expected=%d actual=%d\n",
                message.header.nlmsg_seq, message.header.nlmsg_type, -expected, result);
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
        Message secondary(lane, false);
        secondary.body.ifa_flags |= IFA_F_SECONDARY;
        exchange(fd, secondary, 0);
        verify_address(lane, address(lane), 0xffffff80);
        ioctl_address(lane, SIOCSIFADDR, address(lane, 77));
        verify_address(lane, address(lane, 77), 0xff000000);
        ioctl_address(lane, SIOCSIFADDR, 0);
        verify_address(lane, 0);
        if (!native) {
            for (unsigned kind = 0; kind < 10; kind++) {
                Message invalid(lane, false);
                int expected = EINVAL;
                switch (kind) {
                case 0:
                    invalid.body.ifa_prefixlen = 33;
                    break;
                case 1:
                    invalid.body.ifa_family = AF_UNIX;
                    expected = EAFNOSUPPORT;
                    break;
                case 2:
                    invalid.body.ifa_flags |= IFA_F_TENTATIVE;
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
                case 9:
                    invalid.body.ifa_family = AF_INET6;
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
            value.scope == expected.scope && value.preferred_source == expected.preferred_source &&
            value.tos == expected.tos)
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

static int raw_route(const net::Route& value, bool remove, bool exclusive = true) {
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
    int one = 1;
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    check(fd >= 0 && setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one)) == 0 &&
              bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0,
          "independent route mutation socket");
    uint8_t bytes[128]{};
    static uint32_t sequence = 5000;
    nlmsghdr header{};
    header.nlmsg_type = remove ? RTM_DELROUTE : RTM_NEWROUTE;
    header.nlmsg_flags =
        NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | (exclusive ? NLM_F_EXCL : 0));
    header.nlmsg_seq = ++sequence;
    rtmsg route{};
    route.rtm_family = AF_INET;
    route.rtm_table = RT_TABLE_MAIN;
    route.rtm_protocol = value.protocol;
    route.rtm_tos = value.tos;
    route.rtm_scope = value.scope;
    route.rtm_type = RTN_UNICAST;
    for (uint32_t mask = value.mask; mask & 0x80000000; mask <<= 1)
        route.rtm_dst_len++;
    memcpy(bytes + sizeof(header), &route, sizeof(route));
    size_t size = sizeof(header) + sizeof(route);
    auto attribute = [&](unsigned type, uint32_t number) {
        rtattr field{8, uint16_t(type)};
        memcpy(bytes + size, &field, sizeof(field));
        memcpy(bytes + size + 4, &number, 4);
        size += 8;
    };
    if (value.mask)
        attribute(RTA_DST, htonl(value.destination));
    if (value.gateway)
        attribute(RTA_GATEWAY, htonl(value.gateway));
    if (value.metric)
        attribute(RTA_PRIORITY, value.metric);
    attribute(RTA_OIF, value.index);
    header.nlmsg_len = size;
    memcpy(bytes, &header, sizeof(header));
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    check(sendto(fd, bytes, size, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) ==
              ssize_t(size),
          "submit independent route attributes");
    pollfd ready{fd, POLLIN, 0};
    check(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN),
          "independent route acknowledgment arrives");
    uint8_t reply[128];
    ssize_t count = recv(fd, reply, sizeof(reply), 0);
    nlmsghdr response;
    int error;
    check(count == 36, "independent capped acknowledgment size");
    memcpy(&response, reply, sizeof(response));
    memcpy(&error, reply + sizeof(response), 4);
    check(response.nlmsg_type == NLMSG_ERROR && response.nlmsg_seq == sequence && error <= 0 &&
              error >= -4095 && close(fd) == 0,
          "independent route acknowledgment identity and errno");
    return -error;
}

static void route_variants(const net::Store& runtime) {
    net::Configuration owner;
    net::Routing observer;
    auto initial = parameters(0), changed = parameters(0, 0xffffff80);
    check(owner.open(interfaces[0], runtime) == 0 && observer.open() == 0 &&
              owner.apply(address(0), initial, 2001) == 0,
          "prepare independent route aliases");
    net::Route first{0xcb007200,  0xffffff00,   0, 3007, interfaces[0].index,
                     RTPROT_BOOT, RT_SCOPE_LINK};
    auto second = first;
    second.protocol = RTPROT_STATIC;
    check(raw_route(first, false) == 0 && raw_route(second, false, false) == 0 &&
              raw_route(second, false, false) == EEXIST && contains(observer, first) &&
              contains(observer, second),
          "nonexclusive creation preserves distinct protocol aliases and rejects duplicates");
    check(owner.apply(address(0, 41), changed, 2001) == 0 && contains(observer, first) &&
              contains(observer, second),
          "address replacement preserves every independent alias at one priority");
    check(owner.withdraw() == 0 && contains(observer, first) && contains(observer, second),
          "final-address withdrawal preserves every independent alias");
    check(raw_route(first, true) == 0 && raw_route(second, true) == 0,
          "release each exact protocol alias");
    for (unsigned variant = 0; variant < 2; variant++) {
        check(owner.apply(address(0), initial, 2001) == 0, "prepare zero-priority preservation");
        net::Route manual{
            variant ? address(0) & 0xffffff00 : 0xcb007300, 0xffffff00,   0, 0, interfaces[0].index,
            uint8_t(variant ? RTPROT_KERNEL : RTPROT_BOOT), RT_SCOPE_LINK};
        if (variant)
            check(raw_route(manual, true) == 0,
                  "remove the address-derived route before explicit recreation");
        check(raw_route(manual, false) == 0 && contains(observer, manual),
              "create a manual zero-priority route without a preferred-source attribute");
        check(owner.apply(address(0, 41), initial, 2001) == 0 && contains(observer, manual),
              "manual zero-priority route coexists with the replacement automatic prefix");
        check(owner.withdraw() == 0 && contains(observer, manual),
              "zero priority and a kernel protocol tag do not transfer manual ownership");
        verify_address(0, 0);
        check(raw_route(manual, true) == 0, "release zero-priority route");
    }
    puts("CONFIGURATION_ROUTE_VARIANTS_PASS aliases=2 zero_priority=2");
}

static void tos_ownership(const net::Store& runtime) {
    net::Configuration owner;
    net::Routing observer;
    auto lease = parameters(0);
    lease.classless = true;
    lease.route_count = 1;
    lease.routes[0] = {0xc6336400, 0xffffff00, 0};
    check(owner.open(interfaces[0], runtime) == 0 && observer.open() == 0 &&
              owner.apply(address(0), lease, 2001) == 0,
          "prepare an owned direct route beside independent TOS aliases");
    net::Route owned_route{0xc6336400,  0xffffff00,   0, 2001, interfaces[0].index,
                           RTPROT_DHCP, RT_SCOPE_LINK};
    auto first = owned_route, second = owned_route;
    first.tos = 16;
    second.tos = 8;
    check(raw_route(first, false) == 0 && raw_route(second, false) == 0 &&
              contains(observer, first) && contains(observer, second),
          "different TOS values distinguish otherwise identical manual routes");
    check(owner.apply(address(0, 41), lease, 2001) == 0 && contains(observer, owned_route) &&
              contains(observer, first) && contains(observer, second),
          "replacement retains both manual TOS aliases beside the owned route");
    check(owner.withdraw() == 0 && !contains(observer, owned_route) && contains(observer, first) &&
              contains(observer, second),
          "withdrawal removes only the owned zero-TOS route");
    check(raw_route(first, true) == 0 && !contains(observer, first) && contains(observer, second) &&
              raw_route(second, true) == 0,
          "each exact TOS alias has independent deletion and ownership");
    puts("CONFIGURATION_TOS_OWNERSHIP_PASS aliases=2");
}

static void route_lifetime(const net::Store& runtime) {
    net::Configuration owner;
    net::Routing observer;
    net::Route foreign{0xcb007100,  0xffffff00,   0, 3001, interfaces[0].index,
                       RTPROT_BOOT, RT_SCOPE_LINK};
    check(owner.open(interfaces[0], runtime) == 0 && observer.open() == 0 &&
              owner.apply(address(0), parameters(0), 2001) == 0,
          "prepare final-address route lifetime");
    check(observer.change(foreign, false) == 0 && contains(observer, foreign),
          "install independently owned direct route");
    check(owner.withdraw() == 0, "withdraw the final owned address");
    verify_address(0, 0);
    check(contains(observer, foreign),
          "withdrawing final owned address preserves unrelated direct route");
    check(observer.change(foreign, true) == 0, "release route lifetime fixture");
    puts("CONFIGURATION_ROUTE_LIFETIME_PASS");
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
        verify_address(lane, address(lane, 77), 0xff000000);
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

static int interruption_stage = -1;
extern "C" ssize_t __real_sendto(int, const void*, size_t, int, const sockaddr*, socklen_t);

extern "C" ssize_t __wrap_sendto(int fd, const void* packet, size_t size, int flags,
                                 const sockaddr* destination, socklen_t length) {
    int stage = -1;
    if (interruption_stage >= 0 && size >= 28) {
        const auto* bytes = static_cast<const uint8_t*>(packet);
        nlmsghdr header;
        memcpy(&header, bytes, sizeof(header));
        if (header.nlmsg_type == RTM_DELADDR || header.nlmsg_type == RTM_NEWADDR) {
            ifaddrmsg address;
            memcpy(&address, bytes + 16, sizeof(address));
            if (address.ifa_index == interfaces[1].index)
                stage = header.nlmsg_type == RTM_DELADDR ? 2 : 3;
        } else if (header.nlmsg_type == RTM_DELROUTE || header.nlmsg_type == RTM_NEWROUTE) {
            rtmsg route;
            memcpy(&route, bytes + 16, sizeof(route));
            uint32_t metric = 0;
            for (size_t at = 28; at + 4 <= size;) {
                rtattr field;
                memcpy(&field, bytes + at, sizeof(field));
                if (field.rta_len < 4 || field.rta_len > size - at)
                    break;
                if (field.rta_type == RTA_PRIORITY && field.rta_len == 8)
                    memcpy(&metric, bytes + at + 4, 4);
                at += RTA_ALIGN(field.rta_len);
            }
            if (route.rtm_protocol == RTPROT_DHCP && metric == 2002)
                stage = header.nlmsg_type == RTM_DELROUTE ? 1 : route.rtm_dst_len ? 4 : 5;
        }
        if (!interruption_stage && stage == 1)
            _exit(0); // The production intent is durable; no route has changed.
    }
    ssize_t result = __real_sendto(fd, packet, size, flags, destination, length);
    if (interruption_stage > 0 && stage == interruption_stage && result == ssize_t(size))
        _exit(0); // Exit after the real kernel request, before consuming its ACK.
    return result;
}

static void partial_recovery(const net::Store& runtime, const char* directory) {
    constexpr unsigned lane = 1, metric = 2002;
    char path[300];
    snprintf(path, sizeof(path), "%s/%s.owned", directory, interfaces[lane].name);
    auto before = parameters(lane), after = parameters(lane, 0xffffff80);
    after.route_count = 1;
    after.routes[0] = {0xc6336400, 0xffffff00, 0};
    net::Configuration owner;
    uint8_t old_record[4096], new_record[4096], intent[4096];
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
    // Each child leaves a real kernel state at one replacement stage and exits.
    // Its intent and saved foreign route come from the production journal.
    net::Route foreign{0xcb007100,  0xffffff00,   0, 3002, interfaces[lane].index,
                       RTPROT_BOOT, RT_SCOPE_LINK};
    net::Routing observer;
    check(observer.open() == 0, "partial-replacement observer");
    for (unsigned phase = 0; phase < 8; phase++) {
        unsigned stage = phase < 6 ? phase : 2;
        pid_t child = fork();
        check(child >= 0, "fork partially replaced owner");
        if (!child) {
            net::Configuration current;
            net::Routing writer;
            check(current.open(interfaces[lane], runtime) == 0 &&
                      current.apply(address(lane), before, metric) == 0 && writer.open() == 0 &&
                      writer.change(foreign, false) == 0,
                  "prepare recorded old and independent manual state");
            interruption_stage = stage;
            current.apply(address(lane, 41), after, metric);
            check(false, "production replacement must reach the selected interruption");
            _exit(1);
        }
        int status;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
              "actual owner exits at a recorded replacement boundary");
        verify_address(lane,
                       stage < 2    ? address(lane)
                       : stage == 2 ? 0
                                    : address(lane, 41),
                       stage < 2 ? before.mask : after.mask);
        check(owned(observer, lane) == (stage == 0  ? 1u
                                        : stage < 4 ? 0u
                                                    : stage - 3),
              "independent observer confirms each partial route state");
        check(contains(observer, foreign) == (stage < 2 || stage >= 4),
              "actual final-address cleanup removes the manual route before restoration");
        size_t intent_size = read_file(path, intent, sizeof(intent));
        printf("CONFIGURATION_INTENT_RECORD phase=%u address=%08x owned=%zu foreign=%u length=%zu "
               "data=",
               phase, ioctl_address(lane, SIOCGIFADDR), owned(observer, lane),
               unsigned(contains(observer, foreign)), intent_size);
        for (size_t n = 0; n < intent_size; n++)
            printf("%02x", intent[n]);
        putchar('\n');
        check(intent_size > 144 && !memcmp(intent + 132, "AXNPRSV1", 8),
              "production intent persists the exact route before destructive mutation");
        if (phase == 2) {
            for (unsigned kind = 0; kind < 8; kind++) {
                uint8_t corrupt[4096];
                memcpy(corrupt, intent, intent_size);
                switch (kind) {
                case 0:
                    corrupt[132] ^= 1;
                    break;
                case 1:
                    journal_word(corrupt + 140, UINT32_MAX);
                    break;
                case 2:
                    journal_word(corrupt + 144, 0);
                    break;
                case 3:
                    corrupt[148] = RTM_DELROUTE;
                    break;
                case 4:
                    corrupt[160] = AF_INET6;
                    break;
                case 5:
                    corrupt[161] = 33;
                    break;
                case 6: {
                    bool changed = false;
                    for (size_t at = 172; at + 4 <= intent_size;) {
                        rtattr field;
                        memcpy(&field, corrupt + at, sizeof(field));
                        check(field.rta_len >= 4 && field.rta_len <= intent_size - at,
                              "bounded retained attribute fixture");
                        if (field.rta_type == RTA_OIF) {
                            journal_word(corrupt + at + 4, 99);
                            changed = true;
                            break;
                        }
                        at += RTA_ALIGN(field.rta_len);
                    }
                    check(changed, "retained record has its real output interface");
                    break;
                }
                case 7:
                    journal_word(corrupt + 172, UINT32_MAX);
                    break;
                }
                journal_checksum(corrupt, intent_size);
                write_file(path, corrupt, intent_size);
                net::Configuration rejected;
                check(rejected.open(interfaces[lane], runtime) == EINVAL &&
                          rejected.apply(address(lane), before) == EBADF &&
                          !owned(observer, lane) && !contains(observer, foreign),
                      "reopened corrupt preservation cannot change kernel state");
                verify_address(lane, 0);
            }
            write_file(path, intent, intent_size);
        }
        auto manual = foreign;
        if (phase == 6)
            manual.protocol = RTPROT_STATIC;
        if (phase == 7)
            manual.index = interfaces[0].index;
        if (phase >= 6)
            check(observer.change(manual, false) == 0, "install manual replacement after exit");
        net::Configuration restarted;
        check(restarted.open(interfaces[lane], runtime) == 0 && !owned(observer, lane) &&
                  contains(observer, manual),
              "intent recovery clears either owned tuple and retains the unrelated route");
        if (phase >= 6)
            check(!contains(observer, foreign), "manual replacement wins over saved preservation");
        verify_address(lane, 0);
        printf("CONFIGURATION_INTENT_RESTORED phase=%u address=%08x owned=%zu foreign=%u "
               "protocol=%u index=%u\n",
               phase, ioctl_address(lane, SIOCGIFADDR), owned(observer, lane),
               unsigned(contains(observer, manual)), manual.protocol, manual.index);
        check(observer.change(manual, true) == 0, "release manual boundary fixture route");
    }
    puts("CONFIGURATION_INTENT_RECOVERY_PASS phases=8 original=6 preservation_controls=8 "
         "conflicts=2");
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

static void preservation_bound(const net::Store& runtime) {
    net::Configuration owner;
    net::Routing observer;
    auto initial = parameters(0), desired = parameters(0);
    check(owner.open(interfaces[0], runtime) == 0 && observer.open() == 0 &&
              owner.apply(address(0), initial, 2001) == 0,
          "prepare real ownership-journal capacity");
    net::Route manual[57];
    for (unsigned n = 0; n < 57; n++) {
        manual[n] = {0x64400000 + (n << 8), 0xffffff00,   0, 7000 + n, interfaces[0].index,
                     RTPROT_BOOT,           RT_SCOPE_LINK};
        check(observer.change(manual[n], false) == 0, "install real preservation-capacity routes");
    }
    desired.route_count = dhcp::max_routes;
    for (unsigned n = 0; n < dhcp::max_routes; n++)
        desired.routes[n] = {0xac100000 + (n << 8), 0xffffff00, 0};
    check(owner.apply(address(0, 41), desired, 2001) == ENOSPC && owned(observer, 0) == 1,
          "oversized preservation intent fails before replacing owned kernel state");
    verify_address(0, address(0), initial.mask);
    for (const auto& value : manual)
        check(contains(observer, value), "journal-capacity refusal preserves every manual route");
    for (const auto& value : manual)
        check(observer.change(value, true) == 0, "release preservation-capacity route");
    check(owner.apply(address(0, 41), desired, 2001) == 0 &&
              owned(observer, 0) == dhcp::max_routes + 1 && owner.withdraw() == 0,
          "same description retries after capacity is available without stale restoration");
    verify_address(0, 0);
    puts("CONFIGURATION_PRESERVATION_BOUND_PASS manual_routes=57");
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
        printf("CONFIGURATION_INTERFACE lane=%u index=%u name=%s\n", lane, interfaces[lane].index,
               interfaces[lane].name);
    }
    message_contract(native);
    if (!native)
        address_pressure();
    {
        char directory[100];
        snprintf(directory, sizeof(directory), "/tmp/axiom64-network-owner-%ld", long(getpid()));
        net::Store runtime(directory);
        route_lifetime(runtime);
        route_variants(runtime);
        if (native)
            tos_ownership(runtime);
        recovery(runtime);
        manual_preservation(runtime);
        corrupt_journal(runtime, directory);
        journal_failure(runtime, directory);
        partial_recovery(runtime, directory);
        process_recovery(runtime);
        if (native)
            preservation_bound(runtime);
        else
            rollback(runtime);
    }
    puts("CONFIGURATION_TESTS_PASS");
}
