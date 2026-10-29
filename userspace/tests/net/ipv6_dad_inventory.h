// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

struct address_record {
    struct in6_addr address;
    uint32_t flags, preferred, valid;
};

struct route_record {
    struct in6_addr destination, gateway;
    unsigned prefix, metric, protocol;
    int32_t expires;
};

struct inventory {
    struct address_record addresses[16];
    struct route_record routes[64];
    unsigned address_count, route_count;
};

static void scalar(const char* scope, const char* property, int value) {
    char path[128], bytes[32];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", scope, property);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    check(fd >= 0, "router configuration file");
    int size = snprintf(bytes, sizeof(bytes), "%d\n", value);
    check(write(fd, bytes, size) == size, "router configuration value");
    close(fd);
}

static struct in6_addr prefix_address(unsigned lane, unsigned kind, int generated) {
    struct in6_addr value = {0};
    value.s6_addr[0] = 0x20;
    value.s6_addr[1] = 1;
    value.s6_addr[2] = 0x0d;
    value.s6_addr[3] = 0xb8;
    value.s6_addr[5] = 0x40 + lane;
    value.s6_addr[7] = kind;
    if (generated) {
        memcpy(value.s6_addr + 8, macs[lane], 3);
        value.s6_addr[8] ^= 2;
        value.s6_addr[11] = 0xff;
        value.s6_addr[12] = 0xfe;
        memcpy(value.s6_addr + 13, macs[lane] + 3, 3);
    }
    return value;
}

static void dump(unsigned lane, unsigned type, struct inventory* inventory) {
    static unsigned sequence;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "router inventory socket");

    struct {
        struct nlmsghdr header;
        unsigned char body[12];
    } request = {0};

    request.header.nlmsg_len = NLMSG_LENGTH(type == RTM_GETADDR ? 8 : 12);
    request.header.nlmsg_type = type;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = ++sequence;
    request.body[0] = AF_INET6;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &request, request.header.nlmsg_len, 0, (struct sockaddr*)&kernel,
                 sizeof(kernel)) == request.header.nlmsg_len,
          "router inventory request");
    for (;;) {
        union {
            uint64_t alignment;
            unsigned char bytes[16384];
        } buffer;

        readable(fd, POLLIN);
        int size = recv(fd, buffer.bytes, sizeof(buffer.bytes), 0);
        check(size > 0, "router inventory receive");
        for (struct nlmsghdr* header = (struct nlmsghdr*)buffer.bytes; NLMSG_OK(header, size);
             header = NLMSG_NEXT(header, size)) {
            check(header->nlmsg_seq == sequence, "router inventory sequence");
            if (header->nlmsg_type == NLMSG_DONE) {
                close(fd);
                return;
            }
            check(header->nlmsg_type == (type == RTM_GETADDR ? RTM_NEWADDR : RTM_NEWROUTE),
                  "router inventory record type");
            if (type == RTM_GETADDR) {
                check(header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                      "address record");
                struct ifaddrmsg* message = NLMSG_DATA(header);
                if (message->ifa_index != indices[lane])
                    continue;
                struct address_record value = {.flags = message->ifa_flags};
                int left = IFA_PAYLOAD(header), found = 0;
                for (struct rtattr* field = IFA_RTA(message); RTA_OK(field, left);
                     field = RTA_NEXT(field, left)) {
                    if (field->rta_type == IFA_ADDRESS && RTA_PAYLOAD(field) == 16) {
                        memcpy(&value.address, RTA_DATA(field), 16);
                        found = 1;
                    } else if (field->rta_type == IFA_FLAGS && RTA_PAYLOAD(field) == 4)
                        memcpy(&value.flags, RTA_DATA(field), 4);
                    else if (field->rta_type == IFA_CACHEINFO &&
                             RTA_PAYLOAD(field) >= sizeof(struct ifa_cacheinfo)) {
                        struct ifa_cacheinfo cache;
                        memcpy(&cache, RTA_DATA(field), sizeof(cache));
                        value.preferred = cache.ifa_prefered;
                        value.valid = cache.ifa_valid;
                    }
                }
                check(found && inventory->address_count < 16, "bounded address inventory");
                inventory->addresses[inventory->address_count++] = value;
            } else {
                check(header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg)), "route record");
                struct rtmsg* message = NLMSG_DATA(header);
                struct route_record value = {.prefix = message->rtm_dst_len,
                                             .protocol = message->rtm_protocol};
                unsigned index = 0, table = message->rtm_table;
                int left = RTM_PAYLOAD(header);
                for (struct rtattr* field = RTM_RTA(message); RTA_OK(field, left);
                     field = RTA_NEXT(field, left)) {
                    unsigned char* data = RTA_DATA(field);
                    unsigned length = RTA_PAYLOAD(field);
                    if (field->rta_type == RTA_OIF && length == 4)
                        memcpy(&index, data, 4);
                    else if (field->rta_type == RTA_TABLE && length == 4)
                        memcpy(&table, data, 4);
                    else if (field->rta_type == RTA_DST && length == 16)
                        memcpy(&value.destination, data, 16);
                    else if (field->rta_type == RTA_GATEWAY && length == 16)
                        memcpy(&value.gateway, data, 16);
                    else if (field->rta_type == RTA_PRIORITY && length == 4)
                        memcpy(&value.metric, data, 4);
                    else if (field->rta_type == RTA_CACHEINFO &&
                             length >= sizeof(struct rta_cacheinfo)) {
                        struct rta_cacheinfo cache;
                        memcpy(&cache, data, sizeof(cache));
                        value.expires = cache.rta_expires;
                    }
                }
                if (index != indices[lane] || table != RT_TABLE_MAIN ||
                    message->rtm_type != RTN_UNICAST)
                    continue;
                check(inventory->route_count < 64, "bounded route inventory");
                inventory->routes[inventory->route_count++] = value;
            }
        }
        check(!size, "complete router inventory framing");
    }
}

static struct inventory snapshot(unsigned lane) {
    struct inventory result = {0};
    dump(lane, RTM_GETADDR, &result);
    dump(lane, RTM_GETROUTE, &result);
    return result;
}

static unsigned routes(const struct inventory* inventory, struct in6_addr destination,
                       unsigned prefix) {
    unsigned count = 0;
    for (unsigned at = 0; at < inventory->route_count; at++) {
        const struct route_record* route = inventory->routes + at;
        count += route->expires >= 0 && route->prefix == prefix &&
                 !memcmp(&route->destination, &destination, 16);
    }
    return count;
}
