// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/wireless_scan.c
 * @brief   Check nl80211 discovery and streaming of a completed scan.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static unsigned discover(int fd, int absent) {
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

int main(int argc, char** argv) {
    int absent = argc == 2 && !strcmp(argv[1], "--absent");
    int observed = argc == 2 && !strcmp(argv[1], "--observed");
    require(argc == 1 || absent || observed, "expected --absent or --observed");
    if (!getuid())
        require(setgid(1000) == 0 && setuid(1000) == 0, "drop root credentials");
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    require(fd >= 0, "open generic netlink");
    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    require(bind(fd, (const struct sockaddr*)&address, sizeof(address)) == 0, "bind local port");
    const unsigned family = discover(fd, absent);
    if (!absent) {
        const unsigned index = if_nametoindex("wlan0");
        require(index, "wireless interface detected");
        check_family_dump(fd, family);
        check_interface(fd, family, index);
        check_stream(fd, family, index, !observed);
    }
    require(close(fd) == 0, "release socket");
    puts(absent ? "WIRELESS_SCAN_ABSENT_PASS" : "WIRELESS_SCAN_STREAM_PASS");
}
