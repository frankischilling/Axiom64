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

static void wire(uint32_t source, uint32_t destination, unsigned lane, unsigned test) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "wire raw socket");
    struct timeval timeout = {5, 0};
    check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "wire deadline");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(source)};
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(destination)};
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
    check(close(fd) == 0, "wire close");
    printf("IPV4_ALIAS_WIRE index=%u case=%u source=%08x destination=%08x\n", lane + 1, test,
           source, destination);
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
    wire(alias, primary + 7, lane, 0);
    wire(other, other + 7, lane, 1);
    check(address_message(index, name, primary, 1) == 0, "primary removal");
    missing(fd, name);
    missing(fd, blue);
    check(query(fd, red, SIOCGIFADDR) == other, "unrelated prefix survives primary removal");
    local_udp(other, lane);
    wire(other, other + 7, lane, 2);
    set(fd, name, SIOCSIFADDR, primary);
    set(fd, name, SIOCSIFNETMASK, 0xffffff00);
    wire(primary, primary + 7, lane, 3);
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
