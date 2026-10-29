// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_receive_wire_fixture.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct WireLink wire_links[2];
static uint32_t sequence_number;

static void field(unsigned char* message, unsigned* length, unsigned type, const void* value,
                  unsigned size) {
    struct rtattr attribute = {.rta_len = (unsigned short)(sizeof(attribute) + size),
                               .rta_type = (unsigned short)type};
    memcpy(message + *length, &attribute, sizeof(attribute));
    memcpy(message + *length + sizeof(attribute), value, size);
    *length += RTA_ALIGN(attribute.rta_len);
}

static int request(unsigned char* message, unsigned length, unsigned type, unsigned flags) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    wire_check(fd >= 0, "network control description");
    struct nlmsghdr header = {.nlmsg_len = length,
                              .nlmsg_type = (unsigned short)type,
                              .nlmsg_flags = (unsigned short)flags,
                              .nlmsg_seq = ++sequence_number};
    memcpy(message, &header, sizeof(header));
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    wire_check(sendto(fd, message, length, 0, (struct sockaddr*)&kernel, sizeof(kernel)) == length,
               "network control request");
    return fd;
}

static void acknowledge(int fd) {
    unsigned char bytes[4096];
    ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
    wire_check(count >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)),
               "network control acknowledgment");
    struct nlmsghdr header;
    struct nlmsgerr reply;
    memcpy(&header, bytes, sizeof(header));
    memcpy(&reply, bytes + NLMSG_HDRLEN, sizeof(reply));
    wire_check(header.nlmsg_type == NLMSG_ERROR && header.nlmsg_seq == sequence_number,
               "matching network control acknowledgment");
    if (reply.error)
        errno = -reply.error;
    wire_check(!reply.error, "successful network control mutation");
    wire_check(!close(fd), "close acknowledged control description");
}

void wire_change_address(unsigned lane, uint32_t value, const char* suffix, int add) {
    unsigned char bytes[128] = {0};
    struct ifaddrmsg address = {
        .ifa_family = AF_INET, .ifa_prefixlen = 24, .ifa_index = wire_links[lane].index};
    memcpy(bytes + NLMSG_HDRLEN, &address, sizeof(address));
    unsigned length = NLMSG_LENGTH(sizeof(address));
    uint32_t local = htonl(value), broadcast = htonl(value | 255);
    field(bytes, &length, IFA_LOCAL, &local, sizeof(local));
    field(bytes, &length, IFA_ADDRESS, &local, sizeof(local));
    if (add) {
        field(bytes, &length, IFA_BROADCAST, &broadcast, sizeof(broadcast));
        char label[IFNAMSIZ];
        int count = snprintf(label, sizeof(label), "eth%u%s", lane, suffix);
        wire_check(count > 0 && count < (int)sizeof(label), "bounded address label");
        field(bytes, &length, IFA_LABEL, label, (unsigned)count + 1);
    }
    acknowledge(request(bytes, length, add ? RTM_NEWADDR : RTM_DELADDR,
                        NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_EXCL : 0)));
}

void wire_change_route_metric(uint32_t target, unsigned index, unsigned metric, int add) {
    unsigned char bytes[96] = {0};
    struct rtmsg route = {.rtm_family = AF_INET,
                          .rtm_dst_len = 32,
                          .rtm_table = RT_TABLE_MAIN,
                          .rtm_protocol = RTPROT_STATIC,
                          .rtm_scope = RT_SCOPE_LINK,
                          .rtm_type = RTN_UNICAST};
    memcpy(bytes + NLMSG_HDRLEN, &route, sizeof(route));
    unsigned length = NLMSG_LENGTH(sizeof(route));
    uint32_t destination = htonl(target);
    field(bytes, &length, RTA_DST, &destination, sizeof(destination));
    field(bytes, &length, RTA_OIF, &index, sizeof(index));
    if (metric)
        field(bytes, &length, RTA_PRIORITY, &metric, sizeof(metric));
    acknowledge(request(bytes, length, add ? RTM_NEWROUTE : RTM_DELROUTE,
                        NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_EXCL : 0)));
}

void wire_change_route(uint32_t target, unsigned index, int add) {
    wire_change_route_metric(target, index, 0, add);
}

static void inventory(unsigned lane, unsigned sequence, unsigned phase, uint32_t target, int routes,
                      unsigned expected, unsigned expected_count, unsigned expected_prefix) {
    unsigned char message[64] = {0};
    unsigned length;
    if (routes) {
        struct rtmsg route = {.rtm_family = AF_INET};
        memcpy(message + NLMSG_HDRLEN, &route, sizeof(route));
        length = NLMSG_LENGTH(sizeof(route));
    } else {
        struct ifaddrmsg address = {.ifa_family = AF_INET};
        memcpy(message + NLMSG_HDRLEN, &address, sizeof(address));
        length = NLMSG_LENGTH(sizeof(address));
    }
    int fd =
        request(message, length, routes ? RTM_GETROUTE : RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
    int done = 0;
    unsigned found = 0, selected_index = 0, selected_metric = UINT32_MAX;
    while (!done) {
        unsigned char bytes[4096];
        ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        wire_check(count >= (ssize_t)sizeof(struct nlmsghdr),
                   "complete network inventory datagram");
        printf(
            "{\"kind\":\"inventory\",\"lane\":%u,\"case\":%u,\"phase\":%u,\"routes\":%d,\"hex\":\"",
            lane, sequence, phase, routes);
        wire_hex(bytes, (size_t)count);
        puts("\"}");
        int remaining = (int)count;
        for (struct nlmsghdr* header = (struct nlmsghdr*)bytes; NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            wire_check(header->nlmsg_seq == sequence_number, "inventory request identity");
            if (header->nlmsg_type == NLMSG_DONE) {
                done = 1;
                continue;
            }
            uint32_t local = 0, output = 0, metric = 0;
            unsigned prefix = 0;
            struct rtattr* attribute;
            int attributes;
            if (routes) {
                wire_check(header->nlmsg_type == RTM_NEWROUTE &&
                               header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg)),
                           "route inventory record");
                struct rtmsg* route = NLMSG_DATA(header);
                prefix = route->rtm_dst_len;
                attribute = RTM_RTA(route);
                attributes = RTM_PAYLOAD(header);
                for (; RTA_OK(attribute, attributes); attribute = RTA_NEXT(attribute, attributes)) {
                    if (RTA_PAYLOAD(attribute) == 4 && attribute->rta_type == RTA_DST)
                        memcpy(&local, RTA_DATA(attribute), 4);
                    if (RTA_PAYLOAD(attribute) == 4 && attribute->rta_type == RTA_OIF)
                        memcpy(&output, RTA_DATA(attribute), 4);
                    if (RTA_PAYLOAD(attribute) == 4 && attribute->rta_type == RTA_PRIORITY)
                        memcpy(&metric, RTA_DATA(attribute), 4);
                }
            } else {
                wire_check(header->nlmsg_type == RTM_NEWADDR &&
                               header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                           "address inventory record");
                struct ifaddrmsg* address = NLMSG_DATA(header);
                prefix = address->ifa_prefixlen;
                output = address->ifa_index;
                attribute = IFA_RTA(address);
                attributes = IFA_PAYLOAD(header);
                for (; RTA_OK(attribute, attributes); attribute = RTA_NEXT(attribute, attributes))
                    if (RTA_PAYLOAD(attribute) == 4 && attribute->rta_type == IFA_LOCAL)
                        memcpy(&local, RTA_DATA(attribute), 4);
            }
            if (ntohl(local) == target && prefix == expected_prefix &&
                (routes || output == wire_links[lane].index)) {
                found++;
                if (metric <= selected_metric) {
                    selected_index = output;
                    selected_metric = metric;
                }
            }
        }
        wire_check(remaining == 0, "bounded inventory records");
    }
    wire_check(found == expected_count && (!expected || selected_index == expected),
               "actual address or route transition readback");
    printf("{\"kind\":\"state\",\"lane\":%u,\"case\":%u,\"phase\":%u,\"routes\":%d,"
           "\"target\":\"%08x\",\"found\":%u,\"index\":%u}\n",
           lane, sequence, phase, routes, target, found, selected_index);
    wire_check(!close(fd), "close inventory description");
}

void wire_inventory(unsigned lane, unsigned sequence, unsigned phase, uint32_t target, int routes,
                    unsigned expected) {
    inventory(lane, sequence, phase, target, routes, expected, !!expected, routes ? 32 : 24);
}

void wire_inventory_paths(unsigned lane, unsigned sequence, unsigned phase, uint32_t target,
                          unsigned expected, unsigned count) {
    inventory(lane, sequence, phase, target, 1, expected, count, 32);
}

void wire_inventory_prefix(unsigned lane, unsigned sequence, unsigned phase, uint32_t target,
                           unsigned prefix, unsigned expected, unsigned count) {
    inventory(lane, sequence, phase, target, 1, expected, count, prefix);
}

void wire_remove_prefix(unsigned lane) {
    unsigned char bytes[64] = {0};
    struct rtmsg route = {.rtm_family = AF_INET,
                          .rtm_dst_len = 24,
                          .rtm_table = RT_TABLE_MAIN,
                          .rtm_protocol = RTPROT_KERNEL,
                          .rtm_scope = RT_SCOPE_LINK,
                          .rtm_type = RTN_UNICAST};
    memcpy(bytes + NLMSG_HDRLEN, &route, sizeof(route));
    unsigned length = NLMSG_LENGTH(sizeof(route));
    uint32_t destination = htonl(wire_prefix(lane) & ~255u), index = wire_links[lane].index;
    field(bytes, &length, RTA_DST, &destination, 4);
    field(bytes, &length, RTA_OIF, &index, 4);
    acknowledge(request(bytes, length, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK));
}

static void open_control(unsigned lane) {
    wire_links[lane].control =
        socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(0x88b9));
    struct sockaddr_ll binding = {.sll_family = AF_PACKET,
                                  .sll_protocol = htons(0x88b9),
                                  .sll_ifindex = (int)wire_links[lane].index};
    wire_check(wire_links[lane].control >= 0 &&
                   !bind(wire_links[lane].control, (struct sockaddr*)&binding, sizeof(binding)),
               "Ethernet barrier description");
}

void wire_reopen_control(unsigned lane) {
    wire_check(!close(wire_links[lane].control), "release notified barrier description");
    open_control(lane);
}

void wire_configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    wire_check(fd >= 0, "interface control description");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        wire_check(!ioctl(fd, SIOCGIFINDEX, &request), "actual ingress interface index");
        wire_links[lane].index = request.ifr_ifindex;
        wire_check(!ioctl(fd, SIOCGIFHWADDR, &request), "actual interface MAC");
        memcpy(wire_links[lane].mac, request.ifr_hwaddr.sa_data, 6);
        request.ifr_flags = IFF_UP;
        wire_check(!ioctl(fd, SIOCSIFFLAGS, &request), "interface activation");
        wire_change_address(lane, wire_primary(lane), "", 1);
        wire_change_address(lane, wire_alias(lane), ":rxs", 1);
        wire_change_address(lane, wire_prefix(lane), ":rxp", 1);
        open_control(lane);
        printf("{\"kind\":\"link\",\"lane\":%u,\"index\":%u,\"mac\":\"", lane,
               wire_links[lane].index);
        wire_hex(wire_links[lane].mac, 6);
        puts("\"}");
    }
    wire_check(!close(fd), "close interface control description");
}

struct WireInput wire_input(unsigned lane, unsigned sequence, unsigned scenario) {
    struct WireInput result = {.source = wire_primary(lane) - 1,
                               .destination = wire_primary(lane),
                               .ttl = (uint8_t)(17 + sequence * 11 % 200),
                               .tos = (uint8_t)(0x6e + sequence * 13)};
    if (scenario == 1 || scenario == 10)
        result.destination = wire_alias(lane);
    if (scenario == 2 || scenario == 5 || scenario == 11)
        result.source = wire_prefix(lane) - 1;
    if (scenario == 2)
        result.destination = wire_prefix(lane);
    if (scenario == 3)
        result.destination = UINT32_MAX;
    if (scenario == 4)
        result.destination = wire_primary(lane) | 255;
    if (scenario == 5)
        result.destination = wire_prefix(lane) | 255;
    if (scenario == 6 || scenario == 7 || scenario == 8 || scenario == 11 || scenario == 12)
        result.destination = wire_group(lane);
    if (scenario == 7 || scenario == 12)
        result.source = 0xcb007100 + (scenario == 7 ? 31 : 61) + lane;
    if (scenario == 8)
        result.source = 0xc0000265 + lane;
    if (scenario == 9)
        result.destination = wire_alias(lane ^ 1);
    return result;
}

void wire_transition(unsigned lane, unsigned sequence, unsigned scenario, unsigned phase) {
    struct WireInput input = wire_input(lane, sequence, scenario);
    unsigned own = wire_links[lane].index, other = wire_links[lane ^ 1].index;
    if ((scenario == 7 || scenario == 12) && phase == 0)
        wire_change_route(input.source, other, 1);
    if (phase == 1) {
        if (scenario == 10)
            wire_change_address(lane, wire_alias(lane), ":rxs", 0);
        if (scenario == 11)
            wire_change_address(lane, wire_prefix(lane), ":rxp", 0);
        if (scenario == 12) {
            wire_change_route(input.source, other, 0);
            wire_change_route(input.source, own, 1);
        }
    }
    if (phase == 2) {
        if (scenario == 10)
            wire_change_address(lane, wire_alias(lane), ":rxs", 1);
        if (scenario == 11)
            wire_change_address(lane, wire_prefix(lane), ":rxp", 1);
        if (scenario == 7 || scenario == 12)
            wire_change_route(input.source, scenario == 12 ? own : other, 0);
    }
    if (scenario == 10 || scenario == 11)
        wire_inventory(lane, sequence, phase, scenario == 10 ? wire_alias(lane) : wire_prefix(lane),
                       0, phase == 1 ? 0 : own);
    if (scenario == 7 || scenario == 8 || scenario == 12)
        wire_inventory(lane, sequence, phase, input.source, 1,
                       scenario == 8 || phase == 2    ? 0
                       : scenario == 12 && phase == 1 ? own
                                                      : other);
}
