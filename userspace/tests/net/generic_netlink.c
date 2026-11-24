// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/generic_netlink.c
 * @brief   Check Generic Netlink controller discovery against the Linux ABI.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct message {
    struct nlmsghdr header;
    struct genlmsghdr generic;
    uint8_t attributes[64];
};

static const struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};

static void put_attr(struct message* request, uint16_t type, const void* data, size_t bytes) {
    const struct nlattr attr = {.nla_len = sizeof(attr) + bytes, .nla_type = type};
    uint8_t* where = (uint8_t*)request + request->header.nlmsg_len;
    assert(request->header.nlmsg_len + NLA_ALIGN(attr.nla_len) <= sizeof(*request));
    memcpy(where, &attr, sizeof(attr));
    memcpy(where + sizeof(attr), data, bytes);
    memset(where + attr.nla_len, 0, NLA_ALIGN(attr.nla_len) - attr.nla_len);
    request->header.nlmsg_len += NLA_ALIGN(attr.nla_len);
}

static struct message query(uint32_t sequence, uint16_t flags) {
    return (struct message){
        .header =
            {
                .nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN,
                .nlmsg_type = GENL_ID_CTRL,
                .nlmsg_flags = NLM_F_REQUEST | flags,
                .nlmsg_seq = sequence,
            },
        .generic = {.cmd = CTRL_CMD_GETFAMILY, .version = 1},
    };
}

static ssize_t receive(int fd, void* bytes, size_t capacity) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
    assert(poll(&poll_fd, 1, 5000) == 1 && (poll_fd.revents & POLLIN));
    struct sockaddr_nl peer;
    socklen_t length = sizeof(peer);
    const ssize_t received = recvfrom(fd, bytes, capacity, 0, (struct sockaddr*)&peer, &length);
    assert(received >= (ssize_t)sizeof(struct nlmsghdr));
    assert(length == sizeof(peer) && peer.nl_family == AF_NETLINK && !peer.nl_pid &&
           !peer.nl_groups);
    return received;
}

static bool inspect_family(const struct nlmsghdr* header) {
    const size_t prefix = NLMSG_HDRLEN + GENL_HDRLEN;
    assert(header->nlmsg_len >= prefix);
    struct genlmsghdr generic;
    const uint8_t* data = (const uint8_t*)header;
    memcpy(&generic, data + NLMSG_HDRLEN, sizeof(generic));
    assert(generic.cmd == CTRL_CMD_NEWFAMILY && generic.version == 2 && !generic.reserved);

    const char name[] = "nlctrl";
    bool have_name = false, have_id = false, have_version = false, have_ops = false;
    uint16_t id = 0;
    uint32_t family_version = 0;
    for (size_t at = prefix; at < header->nlmsg_len;) {
        struct nlattr attr;
        assert(header->nlmsg_len - at >= sizeof(attr));
        memcpy(&attr, data + at, sizeof(attr));
        assert(attr.nla_len >= sizeof(attr) &&
               (size_t)NLA_ALIGN(attr.nla_len) <= header->nlmsg_len - at);
        const uint8_t* value = data + at + sizeof(attr);
        if (attr.nla_type == CTRL_ATTR_FAMILY_NAME)
            have_name =
                attr.nla_len == sizeof(attr) + sizeof(name) && !memcmp(value, name, sizeof(name));
        else if (attr.nla_type == CTRL_ATTR_FAMILY_ID) {
            assert(attr.nla_len == sizeof(attr) + sizeof(id));
            memcpy(&id, value, sizeof(id));
            have_id = true;
        } else if (attr.nla_type == CTRL_ATTR_VERSION) {
            assert(attr.nla_len == sizeof(attr) + sizeof(family_version));
            memcpy(&family_version, value, sizeof(family_version));
            have_version = true;
        } else if (attr.nla_type == CTRL_ATTR_OPS)
            have_ops = attr.nla_len > sizeof(attr);
        at += NLA_ALIGN(attr.nla_len);
    }
    if (!have_name)
        return false;
    assert(have_id && id == GENL_ID_CTRL && have_version && family_version == 2 && have_ops);
    return true;
}

static void transact(int fd, uint32_t port, const struct message* request, int error, bool capped) {
    const size_t size = request->header.nlmsg_len;
    assert(sendto(fd, request, size, 0, (const struct sockaddr*)&kernel, sizeof(kernel)) ==
           (ssize_t)size);
    const bool dump = (request->header.nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
    const bool want_ack = !dump && (request->header.nlmsg_flags & NLM_F_ACK);
    bool found = false, acked = false, done = false;
    do {
        _Alignas(struct nlmsghdr) uint8_t bytes[32768];
        size_t left = (size_t)receive(fd, bytes, sizeof(bytes));
        for (const struct nlmsghdr* head = (const struct nlmsghdr*)bytes; NLMSG_OK(head, left);
             head = NLMSG_NEXT(head, left)) {
            assert(head->nlmsg_seq == request->header.nlmsg_seq && head->nlmsg_pid == port);
            if (head->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr ack;
                assert(head->nlmsg_len >= NLMSG_LENGTH(sizeof(ack)) && !acked);
                memcpy(&ack, NLMSG_DATA(head), sizeof(ack));
                assert(ack.error == -error && !memcmp(&ack.msg, request, sizeof(ack.msg)));
                if (capped || !error) {
                    assert((head->nlmsg_flags & NLM_F_CAPPED) &&
                           head->nlmsg_len == NLMSG_LENGTH(sizeof(ack)));
                } else {
                    const size_t echoed = size - sizeof(ack.msg);
                    assert(!(head->nlmsg_flags & NLM_F_CAPPED) &&
                           head->nlmsg_len >= NLMSG_LENGTH(sizeof(ack) + echoed));
                    assert(!memcmp((const uint8_t*)NLMSG_DATA(head) + sizeof(ack),
                                   (const uint8_t*)request + sizeof(ack.msg), echoed));
                }
                acked = true;
            } else if (head->nlmsg_type == NLMSG_DONE) {
                int status;
                assert(dump && !done && (head->nlmsg_flags & NLM_F_MULTI));
                assert(head->nlmsg_len >= NLMSG_LENGTH(sizeof(status)));
                memcpy(&status, NLMSG_DATA(head), sizeof(status));
                assert(!status);
                done = true;
            } else {
                assert(!error && head->nlmsg_type == GENL_ID_CTRL);
                assert(!!(head->nlmsg_flags & NLM_F_MULTI) == dump);
                found |= inspect_family(head);
            }
        }
        assert(!left);
    } while (error ? !acked : !found || (want_ack && !acked) || (dump && !done));
    assert(!error || !found);
}

int main(void) {
    if (!geteuid())
        assert(!setuid(65534));
    const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    const int route = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    assert(fd >= 0 && route >= 0);
    int protocol = 0;
    socklen_t option = sizeof(protocol);
    assert(!getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &option) &&
           protocol == NETLINK_GENERIC);
    assert(!getsockopt(route, SOL_SOCKET, SO_PROTOCOL, &protocol, &option) &&
           protocol == NETLINK_ROUTE);

    assert(!bind(fd, (const struct sockaddr*)&kernel, sizeof(kernel)));
    struct sockaddr_nl address;
    socklen_t size = sizeof(address);
    assert(!getsockname(fd, (struct sockaddr*)&address, &size) && address.nl_pid &&
           size == sizeof(address));
    assert(!bind(route, (const struct sockaddr*)&address, sizeof(address)));
    int other = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
    assert(other >= 0);
    assert(bind(other, (const struct sockaddr*)&address, sizeof(address)) == -1 &&
           errno == EADDRINUSE);
    assert(!close(other));

    // The same port number still routes requests to different protocol handlers.
    const struct {
        struct nlmsghdr header;
        struct ifinfomsg link;
    } link_request = {
        .header =
            {
                .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .nlmsg_type = RTM_GETLINK,
                .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                .nlmsg_seq = 17,
            },
    };

    assert(sendto(route, &link_request, sizeof(link_request), 0, (const struct sockaddr*)&kernel,
                  sizeof(kernel)) == (ssize_t)sizeof(link_request));
    _Alignas(struct nlmsghdr) uint8_t route_reply[16384];
    receive(route, route_reply, sizeof(route_reply));
    struct nlmsghdr link_header;
    memcpy(&link_header, route_reply, sizeof(link_header));
    assert(link_header.nlmsg_type == RTM_NEWLINK && link_header.nlmsg_seq == 17);
    assert(!close(route));

    const uint16_t id = GENL_ID_CTRL;
    struct message request = query(1, NLM_F_ACK);
    put_attr(&request, CTRL_ATTR_FAMILY_NAME, "nlctrl", sizeof("nlctrl"));
    transact(fd, address.nl_pid, &request, 0, false);
    request = query(2, 0);
    put_attr(&request, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
    transact(fd, address.nl_pid, &request, 0, false);
    request = query(3, NLM_F_DUMP | NLM_F_ACK);
    put_attr(&request, CTRL_ATTR_FAMILY_NAME, "nlctrl", sizeof("nlctrl"));
    transact(fd, address.nl_pid, &request, 0, false);
    request = query(4, 0);
    put_attr(&request, CTRL_ATTR_FAMILY_NAME, "axbadfamily", sizeof("axbadfamily"));
    transact(fd, address.nl_pid, &request, ENOENT, false);
    int enabled = 1;
    assert(!setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &enabled, sizeof(enabled)));
    request.header.nlmsg_seq = 5;
    transact(fd, address.nl_pid, &request, ENOENT, true);
    request = query(6, 0);
    transact(fd, address.nl_pid, &request, EINVAL, true);
    request = query(7, 0);
    put_attr(&request, CTRL_ATTR_FAMILY_NAME, "nlctrl", strlen("nlctrl"));
    transact(fd, address.nl_pid, &request, EINVAL, true);
    request = query(8, 0);
    put_attr(&request, CTRL_ATTR_FAMILY_ID, &id, 1);
    transact(fd, address.nl_pid, &request, ERANGE, true);
    request = query(9, NLM_F_ACK);
    request.generic.cmd = CTRL_CMD_UNSPEC;
    transact(fd, address.nl_pid, &request, EOPNOTSUPP, true);
    const uint16_t unknown = 1023;
    request = query(10, 0);
    put_attr(&request, CTRL_ATTR_FAMILY_ID, &unknown, sizeof(unknown));
    put_attr(&request, CTRL_ATTR_FAMILY_NAME, "nlctrl", sizeof("nlctrl"));
    put_attr(&request, CTRL_ATTR_MAX + 1, &id, sizeof(id));
    transact(fd, address.nl_pid, &request, 0, true);
    request = query(11, 0);
    put_attr(&request, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
    put_attr(&request, CTRL_ATTR_FAMILY_ID, &unknown, sizeof(unknown));
    transact(fd, address.nl_pid, &request, ENOENT, true);
    assert(!close(fd));
    puts("GENERIC_NETLINK_CONTROLLER_PASS");
    return 0;
}
