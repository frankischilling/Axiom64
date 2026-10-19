// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_aliases.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void check(int value, const char* message) {
    if (!value) {
        fprintf(stderr, "IPV4_ALIAS_FAIL %s errno=%d\n", message, errno);
        exit(1);
    }
}

static void set(int fd, const char* label, unsigned long request, uint32_t value) {
    struct ifreq entry = {0};
    strcpy(entry.ifr_name, label);
    struct sockaddr_in* address = (struct sockaddr_in*)&entry.ifr_addr;
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(value);
    check(ioctl(fd, request, &entry) == 0, "address mutation");
}

static uint32_t query(int fd, const char* label, unsigned long request) {
    struct ifreq entry = {0};
    strcpy(entry.ifr_name, label);
    check(ioctl(fd, request, &entry) == 0, "address query");
    return ntohl(((struct sockaddr_in*)&entry.ifr_addr)->sin_addr.s_addr);
}

static void missing(int fd, const char* label) {
    struct ifreq entry = {0};
    strcpy(entry.ifr_name, label);
    check(ioctl(fd, SIOCGIFADDR, &entry) == -1 && errno == EADDRNOTAVAIL, "removed address query");
}

static void local_udp(uint32_t address, unsigned lane) {
    int receiver = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(receiver >= 0 && sender >= 0, "local UDP sockets");
    struct timeval timeout = {2, 0};
    check(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
          "local UDP deadline");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(address)};
    check(bind(receiver, (struct sockaddr*)&local, sizeof(local)) == 0, "bind alias UDP");
    socklen_t size = sizeof(local);
    check(getsockname(receiver, (struct sockaddr*)&local, &size) == 0 && local.sin_port,
          "alias UDP port");
    unsigned char sent[256], received[256];
    for (unsigned n = 0; n < sizeof(sent); n++)
        sent[n] = (unsigned char)(n * 17 + lane * 31);
    check(sendto(sender, sent, sizeof(sent), 0, (struct sockaddr*)&local, sizeof(local)) ==
              sizeof(sent),
          "local alias UDP send");
    check(recv(receiver, received, sizeof(received), 0) == sizeof(received) &&
              !memcmp(sent, received, sizeof(sent)),
          "local alias UDP delivery");
    check(close(receiver) == 0 && close(sender) == 0, "local UDP close");
}

static unsigned checksum(const unsigned char* bytes, size_t length) {
    unsigned sum = 0;
    for (size_t n = 0; n < length; n += 2)
        sum += (unsigned)bytes[n] << 8 | (n + 1 < length ? bytes[n + 1] : 0);
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}

static void wire(uint32_t source, uint32_t destination, unsigned lane, unsigned test,
                 int retained) {
    int fd = retained >= 0 ? retained : socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "wire raw socket");
    struct timeval timeout = {5, 0};
    check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "wire deadline");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(source)};
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(destination)};
    if (retained < 0)
        check(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0, "bind wire source");
    unsigned char body[64], received[128];
    for (unsigned n = 0; n < sizeof(body); n++)
        body[n] = (unsigned char)(n * 17 + lane * 31 + test);
    body[0] = 8;
    body[1] = body[2] = body[3] = 0;
    body[4] = 'A';
    body[5] = 'L';
    body[6] = test;
    body[7] = lane;
    unsigned sum = checksum(body, sizeof(body));
    body[2] = sum >> 8;
    body[3] = sum;
    check(sendto(fd, body, sizeof(body), 0, (struct sockaddr*)&remote, sizeof(remote)) ==
              sizeof(body),
          "alias wire send");
    body[0] = body[2] = body[3] = 0;
    sum = checksum(body, sizeof(body));
    body[2] = sum >> 8;
    body[3] = sum;
    for (;;) {
        ssize_t size = recv(fd, received, sizeof(received), 0);
        check(size >= 20, "alias wire reply deadline");
        if (size == 84 && received[0] == 0x45 && !memcmp(received + 12, &remote.sin_addr, 4) &&
            !memcmp(received + 16, &local.sin_addr, 4) &&
            !memcmp(received + 20, body, sizeof(body))) {
            check(!checksum(received, 20) && !checksum(received + 20, sizeof(body)),
                  "alias wire reply checksum");
            break;
        }
    }
    if (retained < 0)
        check(close(fd) == 0, "wire close");
    printf("IPV4_ALIAS_WIRE index=%u case=%u source=%08x destination=%08x\n", lane + 1, test,
           source, destination);
}

static int connected(uint32_t source, uint32_t destination, int raw) {
    int fd = socket(AF_INET, (raw ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC,
                    raw ? IPPROTO_ICMP : IPPROTO_UDP);
    check(fd >= 0, "retained route socket");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(source)};
    struct sockaddr_in remote = {.sin_family = AF_INET,
                                 .sin_port = raw ? 0 : htons(30000),
                                 .sin_addr.s_addr = htonl(destination)};
    check(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0, "retained route bind");
    check(connect(fd, (struct sockaddr*)&remote, sizeof(remote)) == 0, "retained route connect");
    return fd;
}

static void route_mtu(int fd, int expected) {
    int value = -1;
    socklen_t length = sizeof(value);
    int result = getsockopt(fd, IPPROTO_IP, IP_MTU, &value, &length);
    check(expected < 0 ? result == -1 && errno == -expected
                       : result == 0 && length == sizeof(value) && value == expected,
          "retained route MTU observation");
}

static void device_reset(uint32_t source, uint32_t destination, int raw, const char* name,
                         const void* inaccessible) {
    for (unsigned operation = 0; operation < 3; operation++) {
        int fd = connected(source, destination, raw);
        const void* device = operation == 0 ? name : operation == 1 ? "" : inaccessible;
        socklen_t length = operation == 0 ? strlen(name) + 1 : operation == 1 ? 1 : 0;
        struct sockaddr_in remote = {.sin_family = AF_INET,
                                     .sin_port = raw ? 0 : htons(30000),
                                     .sin_addr.s_addr = htonl(destination)};
        for (unsigned repeat = 0; repeat < 2; repeat++) {
            route_mtu(fd, 1500);
            check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, length) == 0,
                  "successful device binding resets destination");
            route_mtu(fd, -ENOTCONN);
            check(connect(fd, (struct sockaddr*)&remote, sizeof(remote)) == 0,
                  "reconnect selects destination after device binding");
        }
        check(close(fd) == 0, "device reset description close");
    }
}

static void option_control(int fd, unsigned operation) {
    int value = 0;
    socklen_t length = sizeof(value);
    if (operation == 0) {
        check(getsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &value, &length) == 0 &&
                  length == sizeof(value),
              "locked discovery getter");
    } else if (operation == 1) {
        value = IP_PMTUDISC_DO;
        check(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value)) == 0,
              "locked discovery setter");
    } else if (operation == 2) {
        value = 4096;
        check(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) == 0,
              "locked send-buffer setter");
    } else if (operation == 3) {
        value = -1;
        check(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value)) == -1 &&
                  errno == EINVAL,
              "locked discovery validation failure");
    } else if (operation == 4) {
        check(getsockopt(fd, IPPROTO_IP, IP_TTL, &value, &length) == 0 && value == 64,
              "lock-free TTL getter");
    } else if (operation == 5) {
        value = 64;
        check(setsockopt(fd, IPPROTO_IP, IP_TTL, &value, sizeof(value)) == 0,
              "lock-free TTL setter");
    } else {
        check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &length) == 0 && value == 0,
              "lock-free pending error getter");
    }
}

static int address_request(unsigned index, const char* label, uint32_t address, unsigned prefix,
                           int remove) {
    unsigned char packet[128] = {0};
    struct nlmsghdr* header = (struct nlmsghdr*)packet;
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    header->nlmsg_type = remove ? RTM_DELADDR : RTM_NEWADDR;
    header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_EXCL);
    header->nlmsg_seq = 0x414c;
    struct ifaddrmsg* body = NLMSG_DATA(header);
    body->ifa_family = AF_INET;
    body->ifa_prefixlen = remove == 2 ? 0 : prefix;
    body->ifa_index = index;
    const unsigned types[] = {IFA_LOCAL, IFA_ADDRESS, IFA_LABEL};
    uint32_t value = htonl(address);
    for (unsigned n = 0; n < 3; n++) {
        if (remove >= 2 && types[n] == IFA_ADDRESS)
            continue;
        struct rtattr* field = (struct rtattr*)(packet + header->nlmsg_len);
        unsigned size = n == 2 ? strlen(label) + 1 : sizeof(value);
        field->rta_type = types[n];
        field->rta_len = RTA_LENGTH(size);
        memcpy(RTA_DATA(field), n == 2 ? (const void*)label : (const void*)&value, size);
        header->nlmsg_len += RTA_ALIGN(field->rta_len);
    }
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "address netlink socket");
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, packet, header->nlmsg_len, 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              header->nlmsg_len,
          "address netlink request");
    unsigned char reply[256];
    ssize_t length = recv(fd, reply, sizeof(reply), 0);
    check(length >= 0 && (size_t)length >= NLMSG_LENGTH(sizeof(struct nlmsgerr)),
          "address netlink reply");
    const struct nlmsghdr* response = (const struct nlmsghdr*)reply;
    check(response->nlmsg_type == NLMSG_ERROR && response->nlmsg_seq == 0x414c,
          "address netlink ACK identity");
    int error = ((const struct nlmsgerr*)NLMSG_DATA(response))->error;
    check(close(fd) == 0, "address netlink close");
    return error;
}

static int address_message(unsigned index, const char* label, uint32_t address, int remove) {
    return address_request(index, label, address, 24, remove);
}

static void collisions(int fd, unsigned index, const char* name, const char* blue, const char* red,
                       uint32_t primary) {
    check(address_request(index, red, primary, 8, 0) == 0, "same address with another prefix");
    set(fd, blue, SIOCSIFADDR, primary + 1);
    set(fd, blue, SIOCSIFNETMASK, 0xffffff00);
    set(fd, name, SIOCSIFNETMASK, 0xff000000);
    missing(fd, name);
    missing(fd, blue);
    check(query(fd, red, SIOCGIFADDR) == primary, "mask collision retains other prefix");
    check(address_request(index, red, primary, 8, 1) == 0, "remove retained mask collision");
    set(fd, name, SIOCSIFADDR, primary);
    set(fd, name, SIOCSIFNETMASK, 0xffffff00);
    uint32_t target = 0x0a020304 + (index << 8);
    check(address_request(index, red, target, 8, 0) == 0, "address collision fixture");
    set(fd, blue, SIOCSIFADDR, primary + 1);
    set(fd, blue, SIOCSIFNETMASK, 0xffffff00);
    struct ifreq entry = {0};
    strcpy(entry.ifr_name, name);
    struct sockaddr_in* address = (struct sockaddr_in*)&entry.ifr_addr;
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(target);
    check(ioctl(fd, SIOCSIFADDR, &entry) == -1 && errno == EEXIST,
          "address replacement reports insertion collision");
    missing(fd, name);
    missing(fd, blue);
    check(query(fd, red, SIOCGIFADDR) == target, "address collision retains other prefix");
    check(address_request(index, red, target, 8, 1) == 0, "remove retained address collision");
    set(fd, name, SIOCSIFADDR, primary);
    set(fd, name, SIOCSIFNETMASK, 0xffffff00);
}

void ipv4_alias_checks(unsigned lane) {
    uint32_t primary = 0x0a170102 + lane * 256, alias = primary + 1;
    uint32_t other = 0x0a210102 + lane * 256;
    char name[16], blue[16], red[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    snprintf(blue, sizeof(blue), "eth%u:blue", lane);
    snprintf(red, sizeof(red), "eth%u:red", lane);
    unsigned index = if_nametoindex(name);
    check(index != 0, "interface identity");
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "configuration socket");
    set(fd, name, SIOCSIFADDR, primary);
    set(fd, name, SIOCSIFNETMASK, 0xffffff00);
    struct ifreq flags = {0};
    strcpy(flags.ifr_name, name);
    check(ioctl(fd, SIOCGIFFLAGS, &flags) == 0, "link flags query");
    flags.ifr_flags |= IFF_UP;
    check(ioctl(fd, SIOCSIFFLAGS, &flags) == 0, "link up");
    set(fd, blue, SIOCSIFADDR, alias);
    check(query(fd, blue, SIOCGIFNETMASK) == 0xff000000, "new alias classful mask");
    set(fd, blue, SIOCSIFNETMASK, 0xffffff00);
    check(query(fd, name, SIOCGIFADDR) == primary && query(fd, blue, SIOCGIFADDR) == alias,
          "primary and alias stay distinct");
    check(address_message(index, red, other, 0) == 0, "netlink creates another prefix");
    check(query(fd, red, SIOCGIFBRDADDR) == 0, "omitted netlink broadcast stays zero");
    check(address_message(index, red, other, 0) == -EEXIST, "duplicate address rejection");
    check(address_message(index, "independent", other + 1, 0) == 0,
          "netlink label independent of device name");
    check(address_message(index, "independent", other + 1, 2) == 0,
          "local-only removal ignores absent peer prefix");
    check(address_request(index, "edge", other & 0xffffff00, 32, 0) == 0,
          "create host address ending in zero");
    check(address_request(index, "edge", other & 0xffffff00, 24, 3) == 0,
          "local-only removal ignores prefix host bits");
    local_udp(alias, lane);
    local_udp(other, lane);
    struct ifreq entries[40];
    struct ifconf list = {.ifc_len = sizeof(entries), .ifc_buf = (char*)entries};
    check(ioctl(fd, SIOCGIFCONF, &list) == 0 && list.ifc_len % sizeof(struct ifreq) == 0,
          "whole address inventory entries");
    unsigned found = 0;
    for (unsigned n = 0; n < (unsigned)list.ifc_len / sizeof(struct ifreq); n++)
        if ((!strcmp(entries[n].ifr_name, blue) &&
             ntohl(((struct sockaddr_in*)&entries[n].ifr_addr)->sin_addr.s_addr) == alias) ||
            (!strcmp(entries[n].ifr_name, red) &&
             ntohl(((struct sockaddr_in*)&entries[n].ifr_addr)->sin_addr.s_addr) == other))
            found++;
    check(found == 2, "enumeration retains both alias labels and values");
    wire(alias, primary + 7, lane, 0, -1);
    wire(other, other + 7, lane, 1, -1);
    int removed[2], shared[2], retained[2], locked[2][4], lock_free[2][3], value_fault[2],
        device_error[2];
    void* inaccessible = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(inaccessible != MAP_FAILED, "option copy-fault page");
    for (unsigned raw = 0; raw < 2; raw++) {
        device_reset(alias, primary + 7, raw, name, inaccessible);
        removed[raw] = connected(alias, primary + 7, raw);
        shared[raw] = dup(removed[raw]);
        check(shared[raw] >= 0, "shared retained route descriptor");
        retained[raw] = connected(other, other + 7, raw);
        route_mtu(removed[raw], 1500);
        route_mtu(retained[raw], 1500);
        value_fault[raw] = connected(alias, primary + 7, raw);
        device_error[raw] = connected(alias, primary + 7, raw);
        for (unsigned operation = 0; operation < 4; operation++)
            locked[raw][operation] = connected(alias, primary + 7, raw);
        for (unsigned operation = 0; operation < 3; operation++)
            lock_free[raw][operation] = connected(alias, primary + 7, raw);
    }
    check(address_message(index, name, primary, 1) == 0, "primary removal");
    missing(fd, name);
    missing(fd, blue);
    check(query(fd, red, SIOCGIFADDR) == other, "unrelated prefix survives primary removal");
    for (unsigned raw = 0; raw < 2; raw++) {
        int value = 0;
        socklen_t length = (socklen_t)-1;
        check(getsockopt(removed[raw], IPPROTO_IP, IP_MTU, &value, inaccessible) == -1 &&
                  errno == EFAULT,
              "unreadable option length preserves retained route");
        check(getsockopt(removed[raw], IPPROTO_IP, IP_MTU, &value, &length) == -1 &&
                  errno == EINVAL,
              "negative option length preserves retained route");
        route_mtu(removed[raw], 1500);
        route_mtu(shared[raw], -ENOTCONN);
        route_mtu(removed[raw], -ENOTCONN);
        route_mtu(retained[raw], 1500);
        route_mtu(retained[raw], 1500);
        length = sizeof(value);
        check(getsockopt(value_fault[raw], IPPROTO_IP, IP_MTU, inaccessible, &length) == -1 &&
                  errno == EFAULT,
              "option value fault follows locked release");
        route_mtu(value_fault[raw], -ENOTCONN);
        check(setsockopt(device_error[raw], SOL_SOCKET, SO_BINDTODEVICE, "missing", 8) == -1 &&
                  errno == ENODEV,
              "missing device preserves retained destination");
        check(setsockopt(device_error[raw], SOL_SOCKET, SO_BINDTODEVICE, inaccessible, 1) == -1 &&
                  errno == EFAULT,
              "unreadable device preserves retained destination");
        route_mtu(device_error[raw], 1500);
        route_mtu(device_error[raw], -ENOTCONN);
        for (unsigned operation = 0; operation < 4; operation++) {
            option_control(locked[raw][operation], operation);
            route_mtu(locked[raw][operation], -ENOTCONN);
        }
        for (unsigned operation = 0; operation < 3; operation++) {
            option_control(lock_free[raw][operation], operation + 4);
            route_mtu(lock_free[raw][operation], 1500);
            route_mtu(lock_free[raw][operation], -ENOTCONN);
        }
    }
    check(munmap(inaccessible, 4096) == 0, "option copy-fault page release");
    unsigned char byte = 0x58;
    check(send(removed[0], &byte, 1, 0) == -1 && errno == ENETUNREACH,
          "removed bound source cannot reselect a route");
    local_udp(other, lane);
    wire(other, other + 7, lane, 2, retained[1]);
    set(fd, name, SIOCSIFADDR, primary);
    set(fd, name, SIOCSIFNETMASK, 0xffffff00);
    wire(primary, primary + 7, lane, 3, -1);
    for (unsigned raw = 0; raw < 2; raw++) {
        route_mtu(removed[raw], -ENOTCONN);
        check(close(removed[raw]) == 0 && close(shared[raw]) == 0 && close(retained[raw]) == 0,
              "retained route final close");
        check(close(value_fault[raw]) == 0, "faulted option description close");
        check(close(device_error[raw]) == 0, "device error description close");
        for (unsigned operation = 0; operation < 4; operation++)
            check(close(locked[raw][operation]) == 0, "locked option description close");
        for (unsigned operation = 0; operation < 3; operation++)
            check(close(lock_free[raw][operation]) == 0, "lock-free option description close");
    }
    printf("IPV4_ALIAS_ROUTE_PASS index=%u transports=2 shared_descriptions=2\n", lane + 1);
    check(address_message(index, red, other, 1) == 0, "netlink alias removal");
    set(fd, blue, SIOCSIFADDR, alias);
    set(fd, blue, SIOCSIFADDR, 0);
    missing(fd, blue);
    set(fd, blue, SIOCSIFADDR, alias);
    memset(&flags, 0, sizeof(flags));
    strcpy(flags.ifr_name, blue);
    check(ioctl(fd, SIOCGIFFLAGS, &flags) == 0, "alias device flags");
    flags.ifr_flags &= ~IFF_UP;
    check(ioctl(fd, SIOCSIFFLAGS, &flags) == 0, "alias down deletes only that address");
    missing(fd, blue);
    check(query(fd, name, SIOCGIFADDR) == primary, "primary survives alias down");
    collisions(fd, index, name, blue, red, primary);
    check(close(fd) == 0, "configuration close");
    printf("IPV4_ALIAS_PASS index=%u wire_cases=4 local_udp=3\n", lane + 1);
}
