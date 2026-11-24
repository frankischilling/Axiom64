// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/wireless_scan.c
 * @brief   Check nl80211 discovery and streaming of a completed scan.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct packet {
    struct nlmsghdr header;
    struct genlmsghdr generic;
    uint8_t attrs[24];
};

static void require(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "WIRELESS_SCAN_FAIL %s errno=%d\n", message, errno);
        exit(1);
    }
}

static void send_request(int fd, uint16_t family, uint8_t command, uint16_t flags,
                         uint32_t sequence, uint16_t type, const void* value, size_t size) {
    struct packet request = {0};
    request.header.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    request.header.nlmsg_type = family;
    request.header.nlmsg_flags = NLM_F_REQUEST | flags;
    request.header.nlmsg_seq = sequence;
    request.generic.cmd = command;
    if (type) {
        struct nlattr attr = {.nla_len = (uint16_t)(NLA_HDRLEN + size), .nla_type = type};
        require(NLA_ALIGN(size + NLA_HDRLEN) <= sizeof(request.attrs), "request attribute fits");
        memcpy(request.attrs, &attr, sizeof(attr));
        memcpy(request.attrs + NLA_HDRLEN, value, size);
        request.header.nlmsg_len += NLA_ALIGN(attr.nla_len);
    }
    require(send(fd, &request, request.header.nlmsg_len, 0) == (ssize_t)request.header.nlmsg_len,
            "send request");
}

static const struct nlattr* attribute(const void* bytes, size_t size, uint16_t type) {
    const uint8_t* cursor = bytes;
    while (size >= sizeof(struct nlattr)) {
        const struct nlattr* attr = (const struct nlattr*)cursor;
        const size_t length = NLA_ALIGN(attr->nla_len);
        require(attr->nla_len >= NLA_HDRLEN && length <= size, "valid nested attribute");
        if ((attr->nla_type & NLA_TYPE_MASK) == type)
            return attr;
        cursor += length;
        size -= length;
    }
    return NULL;
}

static const void* payload(const struct nlattr* attr, size_t size) {
    require(attr && (size_t)attr->nla_len == size + NLA_HDRLEN, "attribute payload size");
    return (const uint8_t*)attr + NLA_HDRLEN;
}

static const struct nlattr* message_attribute(const struct nlmsghdr* message, uint16_t type) {
    const size_t header_length = NLMSG_LENGTH(GENL_HDRLEN);
    require(message->nlmsg_len >= header_length, "generic response header");
    return attribute((const uint8_t*)message + header_length, message->nlmsg_len - header_length,
                     type);
}

static void check_error(const struct nlmsghdr* message, int error) {
    require(message->nlmsg_type == NLMSG_ERROR &&
                message->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)),
            "netlink error response");
    const struct nlmsgerr* status = NLMSG_DATA(message);
    require(status->error == -error, "netlink errno");
}

static int receive(int fd, void* bytes, size_t size, int flags) {
    int length = (int)recv(fd, bytes, size, flags);
    require(length > 0 && NLMSG_OK((struct nlmsghdr*)bytes, length), "receive valid message");
    return length;
}

static unsigned discover(int fd, int absent, unsigned* scan_group) {
    const char name[] = "nl80211";
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    send_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, 1, CTRL_ATTR_FAMILY_NAME, name,
                 sizeof(name));
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    require(message->nlmsg_seq == 1, "family sequence");
    if (absent) {
        check_error(message, ENOENT);
        return 0;
    }
    require(message->nlmsg_type == GENL_ID_CTRL, "completed AX201 scan is available");
    uint16_t id;
    memcpy(&id, payload(message_attribute(message, CTRL_ATTR_FAMILY_ID), sizeof(id)), sizeof(id));
    require(id >= GENL_MIN_ID, "wireless family assigned");
    if (scan_group) {
        const struct nlattr* groups = message_attribute(message, CTRL_ATTR_MCAST_GROUPS);
        require(groups && groups->nla_len >= NLA_HDRLEN, "scan multicast groups");
        const struct nlattr* group =
            attribute((const uint8_t*)groups + NLA_HDRLEN, groups->nla_len - NLA_HDRLEN, 1);
        require(group && group->nla_len >= NLA_HDRLEN, "scan multicast group");
        const uint8_t* items = (const uint8_t*)group + NLA_HDRLEN;
        const size_t size = group->nla_len - NLA_HDRLEN;
        require(!memcmp(payload(attribute(items, size, CTRL_ATTR_MCAST_GRP_NAME), 5), "scan", 5),
                "scan multicast group name");
        memcpy(scan_group,
               payload(attribute(items, size, CTRL_ATTR_MCAST_GRP_ID), sizeof(*scan_group)),
               sizeof(*scan_group));
    }
    return id;
}

static void check_family_dump(int fd, unsigned family) {
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    send_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, NLM_F_DUMP, 6, 0, NULL, 0);
    unsigned controller = 0, wireless = 0;
    int done = 0;
    while (!done) {
        int remaining = receive(fd, bytes, sizeof(bytes), 0);
        for (struct nlmsghdr* message = (struct nlmsghdr*)bytes; NLMSG_OK(message, remaining);
             message = NLMSG_NEXT(message, remaining)) {
            require(message->nlmsg_seq == 6, "family dump sequence");
            if (message->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }
            require(message->nlmsg_type == GENL_ID_CTRL, "family dump record");
            uint16_t id;
            memcpy(&id, payload(message_attribute(message, CTRL_ATTR_FAMILY_ID), sizeof(id)),
                   sizeof(id));
            controller += id == GENL_ID_CTRL;
            wireless += id == family;
        }
    }
    require(controller == 1 && wireless == 1, "both families appear once");
}

static void check_interface(int fd, unsigned family, unsigned index) {
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    uint32_t reported;
    send_request(fd, family, NL80211_CMD_GET_INTERFACE, 0, 2, NL80211_ATTR_IFINDEX, &index,
                 sizeof(index));
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    const struct genlmsghdr* generic = NLMSG_DATA(message);
    require(message->nlmsg_type == family && generic->cmd == NL80211_CMD_NEW_INTERFACE,
            "read station interface");
    memcpy(&reported, payload(message_attribute(message, NL80211_ATTR_IFINDEX), sizeof(reported)),
           sizeof(reported));
    require(reported == index, "interface matches routing inventory");
    send_request(fd, family, NL80211_CMD_GET_WIPHY, 0, 3, NL80211_ATTR_IFINDEX, &index,
                 sizeof(index));
    receive(fd, bytes, sizeof(bytes), 0);
    require(message->nlmsg_seq == 3 && message->nlmsg_type == family &&
                generic->cmd == NL80211_CMD_NEW_WIPHY &&
                !memcmp(payload(message_attribute(message, NL80211_ATTR_WIPHY_NAME), 5), "phy0", 5),
            "read associated radio");
}

static void check_bss(const struct nlmsghdr* message, unsigned number, int fixture) {
    const struct genlmsghdr* generic = NLMSG_DATA(message);
    require(generic->cmd == NL80211_CMD_NEW_SCAN_RESULTS && (message->nlmsg_flags & NLM_F_MULTI),
            "scan response command");
    const struct nlattr* bss = message_attribute(message, NL80211_ATTR_BSS);
    require(bss && bss->nla_len >= NLA_HDRLEN, "nested BSS");
    const uint8_t* data = (const uint8_t*)bss + NLA_HDRLEN;
    size_t size = bss->nla_len - NLA_HDRLEN;
    const uint8_t* bssid = payload(attribute(data, size, NL80211_BSS_BSSID), 6);
    payload(attribute(data, size, NL80211_BSS_FREQUENCY), sizeof(uint32_t));
    require(attribute(data, size, NL80211_BSS_INFORMATION_ELEMENTS) != NULL,
            "BSS contains management frame information elements");
    if (!fixture)
        return;
    require(bssid[0] == 2 && bssid[5] == number, "scan order preserved");
    const uint8_t* probe = payload(attribute(data, size, NL80211_BSS_INFORMATION_ELEMENTS), 3600);
    const uint8_t* beacon = payload(attribute(data, size, NL80211_BSS_BEACON_IES), 3600);
    require(probe[2] == 'P' && probe[3599] == 'p' && beacon[2] == 'B' && beacon[3599] == 'b',
            "separate information elements");
    payload(attribute(data, size, NL80211_BSS_PRESP_DATA), 0);
    int32_t signal;
    memcpy(&signal, payload(attribute(data, size, NL80211_BSS_SIGNAL_MBM), sizeof(signal)),
           sizeof(signal));
    require(signal == -5400, "signal uses hundredths of a dBm");
}

static void check_stream(int fd, unsigned family, unsigned index, int fixture) {
    const int receive_buffer = 4096;
    require(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)) == 0,
            "set an 8192-byte receive quota");
    send_request(fd, family, NL80211_CMD_GET_SCAN, NLM_F_DUMP, 4, NL80211_ATTR_IFINDEX, &index,
                 sizeof(index));
    alignas(struct nlmsghdr) uint8_t bytes[8192];
    if (fixture) {
        receive(fd, bytes, sizeof(bytes), MSG_PEEK);
        check_bss((const struct nlmsghdr*)bytes, 1, fixture);
        send_request(fd, family, NL80211_CMD_GET_SCAN, NLM_F_DUMP, 5, NL80211_ATTR_IFINDEX, &index,
                     sizeof(index));
    }
    unsigned count = 0;
    int done = 0, busy = !fixture;
    while (!done || !busy) {
        int remaining = receive(fd, bytes, sizeof(bytes), 0);
        for (struct nlmsghdr* message = (struct nlmsghdr*)bytes; NLMSG_OK(message, remaining);
             message = NLMSG_NEXT(message, remaining)) {
            if (message->nlmsg_seq == 5) {
                check_error(message, EBUSY);
                busy = 1;
                continue;
            }
            require(message->nlmsg_seq == 4, "single dump sequence");
            if (message->nlmsg_type == NLMSG_DONE) {
                require(message->nlmsg_len >= NLMSG_LENGTH(sizeof(int)) &&
                            *(const int*)NLMSG_DATA(message) == 0,
                        "successful multipart completion");
                done = 1;
                continue;
            }
            require(message->nlmsg_type == family && count < 32, "bounded scan response");
            check_bss(message, ++count, fixture);
        }
    }
    if (fixture)
        require(count == 32, "all access points cross the socket quota");
    else
        printf("nl80211 scan results: %u access points\n", count);
}

static void bring_up_interface(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    require(fd >= 0, "open link control socket");
    struct ifreq link = {.ifr_name = "wlan0"};
    require(ioctl(fd, SIOCGIFFLAGS, &link) == 0, "read wireless link flags");
    link.ifr_flags |= IFF_UP;
    require(ioctl(fd, SIOCSIFFLAGS, &link) == 0, "bring up wireless link");
    require(close(fd) == 0, "release link control socket");
}

static void trigger(int fd, unsigned family, unsigned index, unsigned sequence, int error) {
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    send_request(fd, family, NL80211_CMD_TRIGGER_SCAN, NLM_F_ACK, sequence, NL80211_ATTR_IFINDEX,
                 &index, sizeof(index));
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    require(message->nlmsg_seq == sequence, "scan acknowledgment sequence");
    check_error(message, error);
}

static void reject_active_scan(int fd, unsigned family, unsigned index) {
    struct packet request = {
        .header = {.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + 16),
                   .nlmsg_type = family,
                   .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
                   .nlmsg_seq = 15},
        .generic = {.cmd = NL80211_CMD_TRIGGER_SCAN},
    };
    const struct nlattr interface = {.nla_len = 8, .nla_type = NL80211_ATTR_IFINDEX};
    const struct nlattr list = {.nla_len = 8, .nla_type = NL80211_ATTR_SCAN_SSIDS | NLA_F_NESTED};
    const struct nlattr wildcard = {.nla_len = 4, .nla_type = 1};
    memcpy(request.attrs, &interface, sizeof(interface));
    memcpy(request.attrs + 4, &index, sizeof(index));
    memcpy(request.attrs + 8, &list, sizeof(list));
    memcpy(request.attrs + 12, &wildcard, sizeof(wildcard));
    require(send(fd, &request, request.header.nlmsg_len, 0) == (ssize_t)request.header.nlmsg_len,
            "send active scan request");
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    receive(fd, bytes, sizeof(bytes), 0);
    check_error((const struct nlmsghdr*)bytes, EOPNOTSUPP);
}

static void scan_event(int fd, unsigned family, unsigned index, unsigned command) {
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    const struct genlmsghdr* generic = NLMSG_DATA(message);
    uint32_t reported;
    require(!message->nlmsg_seq && !message->nlmsg_pid && message->nlmsg_type == family &&
                generic->cmd == command,
            "asynchronous kernel scan event");
    memcpy(&reported, payload(message_attribute(message, NL80211_ATTR_IFINDEX), sizeof(reported)),
           sizeof(reported));
    require(reported == index, "scan event identifies the interface");
}

static void check_live(int fd, unsigned family, unsigned index, unsigned group, int fixture) {
    require(group &&
                setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) == 0,
            "subscribe to wireless scan events");
    if (fixture)
        trigger(fd, family, index, 10, ENETDOWN);
    bring_up_interface();
    int dump = -1;
    if (fixture) {
        reject_active_scan(fd, family, index);
        dump = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
        require(dump >= 0, "open concurrent dump socket");
        send_request(dump, family, NL80211_CMD_GET_SCAN, NLM_F_DUMP, 20, NL80211_ATTR_IFINDEX,
                     &index, sizeof(index));
    }
    trigger(fd, family, index, 11, 0);
    if (fixture)
        trigger(fd, family, index, 12, EBUSY);
    scan_event(fd, family, index, NL80211_CMD_NEW_SCAN_RESULTS);
    if (fixture) {
        alignas(struct nlmsghdr) uint8_t bytes[8192];
        receive(dump, bytes, sizeof(bytes), 0);
        require(((struct nlmsghdr*)bytes)->nlmsg_type == family, "first old-generation record");
        receive(dump, bytes, sizeof(bytes), 0);
        const struct nlmsghdr* done = (const struct nlmsghdr*)bytes;
        require(done->nlmsg_type == NLMSG_DONE && (done->nlmsg_flags & NLM_F_DUMP_INTR),
                "updated scan interrupts the older dump");
        require(close(dump) == 0, "release concurrent dump socket");
        trigger(fd, family, index, 13, 0);
        scan_event(fd, family, index, NL80211_CMD_SCAN_ABORTED);
        require(setgid(1000) == 0 && setuid(1000) == 0, "drop scan privileges");
        trigger(fd, family, index, 14, EPERM);
    }
    check_stream(fd, family, index, 0);
    puts("WIRELESS_LIVE_SCAN_PASS");
}

int main(int argc, char** argv) {
    int absent = argc == 2 && !strcmp(argv[1], "--absent");
    int observed = argc == 2 && !strcmp(argv[1], "--observed");
    int live = argc == 2 && !strcmp(argv[1], "--live");
    int live_fixture = argc == 2 && !strcmp(argv[1], "--live-fixture");
    require(argc == 1 || absent || observed || live || live_fixture, "wireless test mode");
    if (!getuid() && !live && !live_fixture)
        require(setgid(1000) == 0 && setuid(1000) == 0, "drop root credentials");
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    require(fd >= 0, "open generic netlink");
    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    require(bind(fd, (const struct sockaddr*)&address, sizeof(address)) == 0, "bind local port");
    unsigned group;
    const unsigned family = discover(fd, absent, live || live_fixture ? &group : NULL);
    if (!absent) {
        const unsigned index = if_nametoindex("wlan0");
        require(index, "wireless interface detected");
        check_family_dump(fd, family);
        check_interface(fd, family, index);
        if (live || live_fixture)
            check_live(fd, family, index, group, live_fixture);
        else
            check_stream(fd, family, index, !observed);
    }
    require(close(fd) == 0, "release socket");
    puts(absent ? "WIRELESS_SCAN_ABSENT_PASS" : "WIRELESS_SCAN_STREAM_PASS");
}
