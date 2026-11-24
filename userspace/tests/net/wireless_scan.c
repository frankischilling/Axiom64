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
    uint8_t attrs[256];
};

static void require(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "WIRELESS_SCAN_FAIL %s errno=%d\n", message, errno);
        exit(1);
    }
}

static struct packet make_request(uint16_t family, uint8_t command, uint16_t flags,
                                  uint32_t sequence) {
    struct packet request = {0};
    request.header.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    request.header.nlmsg_type = family;
    request.header.nlmsg_flags = NLM_F_REQUEST | flags;
    request.header.nlmsg_seq = sequence;
    request.generic.cmd = command;
    return request;
}

static void append_attribute(struct packet* request, uint16_t type, const void* value,
                             size_t size) {
    const size_t offset = request->header.nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
    const struct nlattr attr = {.nla_len = (uint16_t)(NLA_HDRLEN + size), .nla_type = type};
    require(offset + NLA_ALIGN(attr.nla_len) <= sizeof(request->attrs), "request attribute fits");
    memcpy(request->attrs + offset, &attr, sizeof(attr));
    if (size)
        memcpy(request->attrs + offset + NLA_HDRLEN, value, size);
    request->header.nlmsg_len += NLA_ALIGN(attr.nla_len);
}

static void send_packet(int fd, const struct packet* request) {
    const size_t size = request->header.nlmsg_len;
    require(send(fd, request, size, 0) == (ssize_t)size, "send request");
}

static void send_request(int fd, uint16_t family, uint8_t command, uint16_t flags,
                         uint32_t sequence, uint16_t type, const void* value, size_t size) {
    struct packet request = make_request(family, command, flags, sequence);
    if (type)
        append_attribute(&request, type, value, size);
    send_packet(fd, &request);
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

static const struct nlattr* nested(const struct nlattr* parent, uint16_t type) {
    require(parent && parent->nla_len >= NLA_HDRLEN, "nested parent");
    return attribute((const uint8_t*)parent + NLA_HDRLEN, parent->nla_len - NLA_HDRLEN, type);
}

static uint32_t read_u32(const struct nlattr* field) {
    uint32_t value;
    memcpy(&value, payload(field, sizeof(value)), sizeof(value));
    return value;
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

static void check_radio(const struct nlmsghdr* message, int live, int fixture) {
    const struct nlattr* bands = message_attribute(message, NL80211_ATTR_WIPHY_BANDS);
    const uint8_t* max_ssids =
        payload(message_attribute(message, NL80211_ATTR_MAX_NUM_SCAN_SSIDS), 1);
    require(*max_ssids == (live ? 20 : 0), "radio advertises its scan SSID limit");
    const struct nlattr* commands = message_attribute(message, NL80211_ATTR_SUPPORTED_COMMANDS);
    if (live)
        require(read_u32(nested(commands, 1)) == NL80211_CMD_TRIGGER_SCAN,
                "radio advertises live scan requests");
    else
        require(!commands, "cached radio lacks live scan commands");

    unsigned total = 0;
    for (unsigned i = 0; i <= NL80211_BAND_5GHZ; ++i) {
        const struct nlattr* band = nested(bands, i);
        if (!band) {
            require(!fixture, "fixture has both bands");
            continue;
        }
        const struct nlattr* rates = nested(band, NL80211_BAND_ATTR_RATES);
        const struct nlattr* frequencies = nested(band, NL80211_BAND_ATTR_FREQS);
        require(read_u32(nested(nested(rates, 1), NL80211_BITRATE_ATTR_RATE)) == (i ? 60u : 10u),
                "band has appropriate legacy rates");
        unsigned count = 0;
        const struct nlattr* entry;
        while ((entry = nested(frequencies, count + 1))) {
            ++count;
            const uint32_t mhz = read_u32(nested(entry, NL80211_FREQUENCY_ATTR_FREQ));
            require((mhz >= 5000) == (i == NL80211_BAND_5GHZ), "frequency matches its band");
            const int disabled = nested(entry, NL80211_FREQUENCY_ATTR_DISABLED) != NULL;
            const int no_ir = nested(entry, NL80211_FREQUENCY_ATTR_NO_IR) != NULL;
            require(live || disabled || no_ir, "cached radio reports passive-only channels");
            if (fixture) {
                require(disabled == (mhz == 2417), "firmware disabled channel preserved");
                require(no_ir == (!disabled && (!live || mhz == 5260)),
                        "restricted channels remain passive-only");
                require((nested(entry, NL80211_FREQUENCY_ATTR_RADAR) != NULL) == (mhz == 5260) &&
                            (nested(entry, NL80211_FREQUENCY_ATTR_INDOOR_ONLY) != NULL) ==
                                (mhz == 5260),
                        "firmware radar and indoor constraints preserved");
            }
        }
        if (fixture)
            require(count == (i ? 37u : 14u), "full band channel list fits");
        total += count;
    }
    require(total, "radio reports channels");
    puts("WIRELESS_RADIO_CHANNELS_PASS");
}

static void check_interface(int fd, unsigned family, unsigned index, int live, int fixture) {
    alignas(struct nlmsghdr) uint8_t bytes[8192];
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
    check_radio(message, live, fixture);
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

static void trigger_ssids(int fd, unsigned family, unsigned index, unsigned sequence,
                          const void* list, size_t size, int error) {
    struct packet request = make_request(family, NL80211_CMD_TRIGGER_SCAN, NLM_F_ACK, sequence);
    append_attribute(&request, NL80211_ATTR_IFINDEX, &index, sizeof(index));
    append_attribute(&request, NL80211_ATTR_SCAN_SSIDS | NLA_F_NESTED, list, size);
    send_packet(fd, &request);
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    require(message->nlmsg_seq == sequence, "SSID scan acknowledgment sequence");
    check_error(message, error);
}

static void check_bad_ssids(int fd, unsigned family, unsigned index) {
    const struct nlattr truncated = {.nla_len = 5, .nla_type = 1};
    trigger_ssids(fd, family, index, 36, &truncated, sizeof(truncated), EINVAL);

    const struct {
        struct nlattr field;
        uint8_t name[36];
    } oversized = {{.nla_len = 37, .nla_type = 1}, {0}};

    trigger_ssids(fd, family, index, 37, &oversized, sizeof(oversized), EINVAL);
    struct nlattr list[21];
    for (unsigned i = 0; i < sizeof(list) / sizeof(list[0]); ++i)
        list[i] = (struct nlattr){.nla_len = NLA_HDRLEN, .nla_type = i + 1};
    trigger_ssids(fd, family, index, 38, list, sizeof(list), EINVAL);
}

static void trigger_filtered(int fd, unsigned family, unsigned index, unsigned sequence,
                             unsigned count, uint32_t first, uint32_t second, int malformed,
                             uint32_t flags, int error) {
    struct packet request = make_request(family, NL80211_CMD_TRIGGER_SCAN, NLM_F_ACK, sequence);

    const struct {
        struct nlattr field;
        uint32_t frequency;
    } entries[] = {
        {{.nla_len = malformed ? 7 : 8, .nla_type = 1}, first},
        {{.nla_len = 8, .nla_type = 2}, second},
    };

    append_attribute(&request, NL80211_ATTR_IFINDEX, &index, sizeof(index));
    append_attribute(&request, NL80211_ATTR_SCAN_FREQUENCIES | NLA_F_NESTED, entries,
                     count * sizeof(entries[0]));
    if (flags)
        append_attribute(&request, NL80211_ATTR_SCAN_FLAGS, &flags, sizeof(flags));
    send_packet(fd, &request);
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    require(message->nlmsg_seq == sequence, "filtered scan acknowledgment sequence");
    check_error(message, error);
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

static void check_live(int fd, unsigned family, unsigned index, unsigned group, int fixture,
                       int active) {
    require(group &&
                setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) == 0,
            "subscribe to wireless scan events");
    if (fixture)
        trigger(fd, family, index, 10, ENETDOWN);
    bring_up_interface();
    int dump = -1;
    if (fixture) {
        check_bad_ssids(fd, family, index);
        trigger_filtered(fd, family, index, 31, 0, 0, 0, 0, 0, EINVAL);
        trigger_filtered(fd, family, index, 32, 1, 5260, 0, 1, 0, EINVAL);
        trigger_filtered(fd, family, index, 33, 1, 1234, 0, 0, 0, EINVAL);
        trigger_filtered(fd, family, index, 34, 1, 2417, 0, 0, 0, EINVAL);
        trigger_filtered(fd, family, index, 35, 2, 5260, 5260, 0, 0, EINVAL);
        const uint32_t colocated = NL80211_SCAN_FLAG_COLOCATED_6GHZ;
        trigger_filtered(fd, family, index, 39, 1, 5260, 0, 0,
                         colocated | NL80211_SCAN_FLAG_RANDOM_ADDR, EOPNOTSUPP);
        dump = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
        require(dump >= 0, "open concurrent dump socket");
        send_request(dump, family, NL80211_CMD_GET_SCAN, NLM_F_DUMP, 20, NL80211_ATTR_IFINDEX,
                     &index, sizeof(index));
        trigger_filtered(fd, family, index, 11, 2, 2417, 5260, 0, colocated, 0);
    } else if (active) {
        const struct nlattr wildcard = {.nla_len = NLA_HDRLEN, .nla_type = 1};
        trigger_ssids(fd, family, index, 11, &wildcard, sizeof(wildcard), 0);
    } else {
        trigger(fd, family, index, 11, 0);
    }
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

        const struct {
            struct nlattr wildcard, directed;
            uint8_t name[4];
            struct nlattr duplicate;
            uint8_t duplicate_name[4];
        } names = {
            {.nla_len = 4, .nla_type = 1},
            {.nla_len = 7, .nla_type = 2},
            {'A', 0, 'B', 0},
            {.nla_len = 7, .nla_type = 3},
            {'A', 0, 'B', 0},
        };

        trigger_ssids(fd, family, index, 13, &names, sizeof(names), 0);
        scan_event(fd, family, index, NL80211_CMD_SCAN_ABORTED);
        trigger_ssids(fd, family, index, 19, &names.wildcard, sizeof(names.wildcard), 0);
        scan_event(fd, family, index, NL80211_CMD_NEW_SCAN_RESULTS);
        require(setgid(1000) == 0 && setuid(1000) == 0, "drop scan privileges");
        trigger(fd, family, index, 14, EPERM);
    }
    check_stream(fd, family, index, 0);
    puts("WIRELESS_LIVE_SCAN_PASS");
}

static void check_station_ack(int fd, const struct packet* request, int error) {
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    send_packet(fd, request);
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    require(message->nlmsg_seq == request->header.nlmsg_seq, "station acknowledgment sequence");
    check_error(message, error);
}

static void check_station_event(int fd, unsigned family, unsigned index, unsigned command,
                                uint16_t expected, const uint8_t* peer) {
    alignas(struct nlmsghdr) uint8_t bytes[1024];
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    const struct genlmsghdr* event = NLMSG_DATA(message);
    require(message->nlmsg_type == family && !message->nlmsg_seq && !message->nlmsg_pid &&
                event->cmd == command,
            "asynchronous station event");
    require(read_u32(message_attribute(message, NL80211_ATTR_IFINDEX)) == index,
            "station event identifies interface");
    if (peer)
        require(!memcmp(payload(message_attribute(message, NL80211_ATTR_MAC), 6), peer, 6),
                "connect event identifies peer");
    const unsigned field =
        command == NL80211_CMD_CONNECT ? NL80211_ATTR_STATUS_CODE : NL80211_ATTR_REASON_CODE;
    uint16_t status;
    memcpy(&status, payload(message_attribute(message, field), sizeof(status)), sizeof(status));
    require(status == expected, "station event carries expected status or reason");
}

static void check_connection(int fd, unsigned family, unsigned index) {
    const char name[] = "nl80211";
    alignas(struct nlmsghdr) uint8_t bytes[8192];
    send_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, 15, CTRL_ATTR_FAMILY_NAME, name,
                 sizeof(name));
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlmsghdr* message = (const struct nlmsghdr*)bytes;
    require(read_u32(message_attribute(message, CTRL_ATTR_MAXATTR)) >= NL80211_ATTR_MLO_SUPPORT,
            "controller reports the supported attribute range");
    const struct nlattr* groups = message_attribute(message, CTRL_ATTR_MCAST_GROUPS);
    const struct nlattr* entry = nested(groups, 2);
    require(!memcmp(payload(nested(entry, CTRL_ATTR_MCAST_GRP_NAME), 5), "mlme", 5),
            "MLME multicast group name");
    const uint32_t group = read_u32(nested(entry, CTRL_ATTR_MCAST_GRP_ID));
    require(setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) == 0,
            "subscribe to connection events");

    send_request(fd, family, NL80211_CMD_GET_WIPHY, 0, 16, NL80211_ATTR_IFINDEX, &index,
                 sizeof(index));
    receive(fd, bytes, sizeof(bytes), 0);
    const struct nlattr* commands = message_attribute(message, NL80211_ATTR_SUPPORTED_COMMANDS);
    require(read_u32(nested(commands, 2)) == NL80211_CMD_CONNECT, "radio advertises connect");
    require(read_u32(nested(commands, 3)) == NL80211_CMD_DISCONNECT, "radio advertises disconnect");
    require(read_u32(nested(commands, 4)) == NL80211_CMD_SET_STATION,
            "radio advertises station authorization");

    struct packet request = make_request(family, NL80211_CMD_CONNECT, NLM_F_ACK, 17);
    const uint8_t peer[] = {2, 0, 0, 0, 0, 1};
    const uint32_t frequency = 2412;
    append_attribute(&request, NL80211_ATTR_IFINDEX, &index, sizeof(index));
    check_station_ack(fd, &request, EINVAL);
    append_attribute(&request, NL80211_ATTR_SSID, "lab", 3);
    append_attribute(&request, NL80211_ATTR_MAC, peer, sizeof(peer));
    append_attribute(&request, NL80211_ATTR_WIPHY_FREQ, &frequency, sizeof(frequency));
    request.header.nlmsg_seq++;
    check_station_ack(fd, &request, ENETDOWN);
    bring_up_interface();
    struct packet privacy = request;
    privacy.header.nlmsg_seq++;
    append_attribute(&privacy, NL80211_ATTR_PRIVACY, NULL, 0);
    check_station_ack(fd, &privacy, EOPNOTSUPP);
    struct packet duplicate = request;
    duplicate.header.nlmsg_seq += 2;
    append_attribute(&duplicate, NL80211_ATTR_SSID, "lab", 3);
    check_station_ack(fd, &duplicate, EINVAL);
    struct packet malformed_ie = request;
    malformed_ie.header.nlmsg_seq += 3;
    const uint8_t invalid_ie[] = {127, 3, 0};
    append_attribute(&malformed_ie, NL80211_ATTR_IE, invalid_ie, sizeof(invalid_ie));
    check_station_ack(fd, &malformed_ie, EINVAL);
    malformed_ie = request;
    malformed_ie.header.nlmsg_seq += 4;
    const uint8_t rsn_ie[] = {48, 2, 1, 0};
    append_attribute(&malformed_ie, NL80211_ATTR_IE, rsn_ie, sizeof(rsn_ie));
    check_station_ack(fd, &malformed_ie, EOPNOTSUPP);

    struct packet leave = make_request(family, NL80211_CMD_DISCONNECT, NLM_F_ACK, 40);
    check_station_ack(fd, &leave, EINVAL);
    append_attribute(&leave, NL80211_ATTR_IFINDEX, &index, sizeof(index));
    leave.header.nlmsg_seq++;
    check_station_ack(fd, &leave, 0); /* Already disconnected. */
    duplicate = leave;
    duplicate.header.nlmsg_seq++;
    const uint16_t invalid = 0;
    append_attribute(&duplicate, NL80211_ATTR_REASON_CODE, &invalid, sizeof(invalid));
    check_station_ack(fd, &duplicate, EINVAL);

    request.header.nlmsg_seq += 3;
    check_station_ack(fd, &request, 0);
    request.header.nlmsg_seq++;
    check_station_ack(fd, &request, EBUSY);
    check_station_event(fd, family, index, NL80211_CMD_CONNECT, 0, peer);
    request.header.nlmsg_seq++;
    check_station_ack(fd, &request, EISCONN);

    const uint16_t reason = 8;
    leave.header.nlmsg_seq += 2;
    struct packet explicit_reason = leave;
    append_attribute(&explicit_reason, NL80211_ATTR_REASON_CODE, &reason, sizeof(reason));
    check_station_ack(fd, &explicit_reason, 0);
    explicit_reason.header.nlmsg_seq++;
    check_station_ack(fd, &explicit_reason, EBUSY);
    request.header.nlmsg_seq++;
    check_station_ack(fd, &request, EBUSY);
    check_station_event(fd, family, index, NL80211_CMD_DISCONNECT, reason, NULL);

    request.header.nlmsg_seq++;
    check_station_ack(fd, &request, 0);
    check_station_event(fd, family, index, NL80211_CMD_CONNECT, 0, peer);
    leave.header.nlmsg_seq += 2;
    check_station_ack(fd, &leave, 0);
    check_station_event(fd, family, index, NL80211_CMD_DISCONNECT, 3, NULL);

    int owner = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    require(owner >= 0, "open separate connection owner socket");
    struct packet owned = request;
    owned.header.nlmsg_seq++;
    const uint8_t extended[] = {127, 1, 0};
    const uint16_t ethertype = 0x888e;
    const uint8_t ht[26] = {0}, vht[12] = {0};
    append_attribute(&owned, NL80211_ATTR_IE, extended, sizeof(extended));
    append_attribute(&owned, NL80211_ATTR_CONTROL_PORT, NULL, 0);
    append_attribute(&owned, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, &ethertype, sizeof(ethertype));
    append_attribute(&owned, NL80211_ATTR_HT_CAPABILITY, ht, sizeof(ht));
    append_attribute(&owned, NL80211_ATTR_HT_CAPABILITY_MASK, ht, sizeof(ht));
    append_attribute(&owned, NL80211_ATTR_VHT_CAPABILITY, vht, sizeof(vht));
    append_attribute(&owned, NL80211_ATTR_VHT_CAPABILITY_MASK, vht, sizeof(vht));
    append_attribute(&owned, NL80211_ATTR_SOCKET_OWNER, NULL, 0);
    append_attribute(&owned, NL80211_ATTR_SOCKET_OWNER, NULL, 0);
    append_attribute(&owned, NL80211_ATTR_MLO_SUPPORT, NULL, 0);
    check_station_ack(owner, &owned, 0);
    check_station_event(fd, family, index, NL80211_CMD_CONNECT, 0, peer);
    leave.header.nlmsg_seq++;
    check_station_ack(fd, &leave, EPERM);
    struct packet authorize = make_request(family, NL80211_CMD_SET_STATION, NLM_F_ACK, 60);
    const uint32_t authorized = 1u << NL80211_STA_FLAG_AUTHORIZED;
    const struct nl80211_sta_flag_update update = {.mask = authorized, .set = authorized};
    append_attribute(&authorize, NL80211_ATTR_IFINDEX, &index, sizeof(index));
    append_attribute(&authorize, NL80211_ATTR_MAC, peer, sizeof(peer));
    check_station_ack(fd, &authorize, EINVAL);
    authorize.header.nlmsg_seq++;
    append_attribute(&authorize, NL80211_ATTR_STA_FLAGS2, &update, sizeof(update));
    check_station_ack(fd, &authorize, 0);
    require(close(owner) == 0, "close connection owner socket");
    check_station_event(fd, family, index, NL80211_CMD_DISCONNECT, 3, NULL);
    require(setgid(1000) == 0 && setuid(1000) == 0, "drop connection privileges");
    request.header.nlmsg_seq++;
    check_station_ack(fd, &request, EPERM);
    leave.header.nlmsg_seq++;
    check_station_ack(fd, &leave, EPERM);
    authorize.header.nlmsg_seq++;
    check_station_ack(fd, &authorize, EPERM);
    puts("WIRELESS_LIVE_CONNECT_PASS");
    puts("WIRELESS_LIVE_DISCONNECT_PASS");
    puts("WIRELESS_CONTROLLED_PORT_PASS");
}

int main(int argc, char** argv) {
    int absent = argc == 2 && !strcmp(argv[1], "--absent");
    int observed = argc == 2 && !strcmp(argv[1], "--observed");
    int active = argc == 2 && !strcmp(argv[1], "--active");
    int live = active || (argc == 2 && !strcmp(argv[1], "--live"));
    int live_fixture = argc == 2 && !strcmp(argv[1], "--live-fixture");
    int connect_fixture = argc == 2 && !strcmp(argv[1], "--connect-fixture");
    require(argc == 1 || absent || observed || live || live_fixture || connect_fixture,
            "wireless test mode");
    if (!getuid() && !live && !live_fixture && !connect_fixture)
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
        check_interface(fd, family, index, live || live_fixture || connect_fixture,
                        live_fixture || connect_fixture || (!observed && !live));
        if (connect_fixture)
            check_connection(fd, family, index);
        else if (live || live_fixture)
            check_live(fd, family, index, group, live_fixture, active);
        else
            check_stream(fd, family, index, !observed);
    }
    require(close(fd) == 0, "release socket");
    puts(absent ? "WIRELESS_SCAN_ABSENT_PASS" : "WIRELESS_SCAN_STREAM_PASS");
}
