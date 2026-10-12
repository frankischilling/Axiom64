// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "NETLINK_INVENTORY_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

static void attributes(struct rtattr** fields, unsigned count, const void* data, int bytes) {
    memset(fields, 0, count * sizeof(*fields));
    struct rtattr* field = (struct rtattr*)data;
    for (; RTA_OK(field, bytes); field = RTA_NEXT(field, bytes)) {
        unsigned kind = field->rta_type & NLA_TYPE_MASK;
        if (kind < count) {
            require(!fields[kind], "duplicate reply attribute");
            fields[kind] = field;
        }
    }
    require(!bytes, "complete aligned reply attributes");
}

static unsigned dump(int fd, int observer, unsigned type, unsigned family, int compact,
                     unsigned sequence, unsigned port) {
    unsigned char packet[16384] = {0};
    struct nlmsghdr* request = (struct nlmsghdr*)packet;
    unsigned body = compact               ? 4
                    : type == RTM_GETLINK ? sizeof(struct ifinfomsg)
                    : type == RTM_GETADDR ? sizeof(struct ifaddrmsg)
                                          : sizeof(struct rtmsg);
    request->nlmsg_len = NLMSG_LENGTH(body);
    request->nlmsg_type = type;
    request->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request->nlmsg_seq = sequence;
    *(unsigned char*)NLMSG_DATA(request) = family;
    if (compact)
        memset((unsigned char*)NLMSG_DATA(request) + 1, 0xa5, 3);
    require(send(fd, packet, request->nlmsg_len, 0) == (ssize_t)request->nlmsg_len, "send dump");
    unsigned records = 0;
    for (unsigned datagram = 0; datagram < 64; datagram++) {
        struct pollfd waiting = {.fd = fd, .events = POLLIN};
        require(poll(&waiting, 1, 3000) == 1 && (waiting.revents & POLLIN), "dump deadline");
        struct sockaddr_nl from;
        struct iovec vector = {.iov_base = packet, .iov_len = sizeof(packet)};
        struct msghdr message = {
            .msg_name = &from, .msg_namelen = sizeof(from), .msg_iov = &vector, .msg_iovlen = 1};
        ssize_t received = recvmsg(fd, &message, 0);
        require(received >= 16 && !(message.msg_flags & MSG_TRUNC) &&
                    from.nl_family == AF_NETLINK && from.nl_pid == 0 && from.nl_groups == 0,
                "complete kernel datagram");
        int left = received;
        for (struct nlmsghdr* record = (struct nlmsghdr*)packet; NLMSG_OK(record, left);
             record = NLMSG_NEXT(record, left)) {
            if (record->nlmsg_type == NLMSG_ERROR) {
                require(record->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)),
                        "complete dump error");
                errno = -((struct nlmsgerr*)NLMSG_DATA(record))->error;
                fprintf(stderr, "NETLINK_INVENTORY_DUMP_ERROR type=%u compact=%d error=%d\n", type,
                        compact, errno);
                require(0, "successful inventory response");
            }
            require(record->nlmsg_seq == sequence && record->nlmsg_pid == port &&
                        (record->nlmsg_flags & NLM_F_MULTI),
                    "reply sequence port and multipart ownership");
            if (record->nlmsg_type == NLMSG_DONE) {
                require(record->nlmsg_len == NLMSG_LENGTH(sizeof(int)) &&
                            *(int*)NLMSG_DATA(record) == 0 && left == (int)record->nlmsg_len,
                        "complete successful dump");
                require(records > 0, "nonempty supported inventory");
                printf("NETLINK_INVENTORY_OBSERVATION type=%u family=%u compact=%d records=%u\n",
                       type, family, compact, records);
                return records;
            }
            if (type == RTM_GETLINK) {
                require(record->nlmsg_type == RTM_NEWLINK &&
                            record->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                        "link reply type and length");
                struct ifinfomsg* link = NLMSG_DATA(record);
                struct rtattr* fields[IFLA_MAX + 1];
                attributes(fields, IFLA_MAX + 1, IFLA_RTA(link), IFLA_PAYLOAD(record));
                require(fields[IFLA_IFNAME] && fields[IFLA_MTU] &&
                            RTA_PAYLOAD(fields[IFLA_IFNAME]) > 1 &&
                            RTA_PAYLOAD(fields[IFLA_IFNAME]) <= IF_NAMESIZE &&
                            RTA_PAYLOAD(fields[IFLA_MTU]) == 4,
                        "link name and mtu attributes");
                char name[IF_NAMESIZE];
                require(if_indextoname(link->ifi_index, name) &&
                            !strcmp(name, RTA_DATA(fields[IFLA_IFNAME])),
                        "independent interface name");
                struct ifreq query = {0};
                strcpy(query.ifr_name, name);
                require(!ioctl(observer, SIOCGIFMTU, &query) &&
                            query.ifr_mtu == *(int*)RTA_DATA(fields[IFLA_MTU]),
                        "independent interface mtu");
                require(!ioctl(observer, SIOCGIFFLAGS, &query) &&
                            (link->ifi_flags & 0xffff) == (unsigned short)query.ifr_flags,
                        "independent interface flags");
                require(fields[IFLA_TXQLEN] && RTA_PAYLOAD(fields[IFLA_TXQLEN]) == 4 &&
                            !ioctl(observer, SIOCGIFTXQLEN, &query) &&
                            query.ifr_qlen == *(int*)RTA_DATA(fields[IFLA_TXQLEN]),
                        "independent software transmit queue length");
                require(link->ifi_type == (!strcmp(name, "lo") ? 772 : 1), "link hardware type");
            } else if (type == RTM_GETADDR) {
                require(record->nlmsg_type == RTM_NEWADDR &&
                            record->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                        "address reply type and length");
                struct ifaddrmsg* address = NLMSG_DATA(record);
                struct rtattr* fields[IFA_MAX + 1];
                attributes(fields, IFA_MAX + 1, IFA_RTA(address), IFA_PAYLOAD(record));
                require(address->ifa_family == AF_INET && address->ifa_prefixlen <= 32 &&
                            fields[IFA_LOCAL] && RTA_PAYLOAD(fields[IFA_LOCAL]) == 4,
                        "IPv4 local address attribute");
                struct ifreq query = {0};
                require(if_indextoname(address->ifa_index, query.ifr_name) != NULL,
                        "address interface");
                require(!ioctl(observer, SIOCGIFADDR, &query) &&
                            ((struct sockaddr_in*)&query.ifr_addr)->sin_addr.s_addr ==
                                *(in_addr_t*)RTA_DATA(fields[IFA_LOCAL]),
                        "independent primary IPv4 address");
                require(!ioctl(observer, SIOCGIFNETMASK, &query), "independent IPv4 mask");
                unsigned mask = ntohl(((struct sockaddr_in*)&query.ifr_netmask)->sin_addr.s_addr);
                unsigned prefix = 0;
                while (mask & 0x80000000u) {
                    prefix++;
                    mask <<= 1;
                }
                require(address->ifa_prefixlen == prefix, "independent IPv4 prefix");
            } else {
                require(record->nlmsg_type == RTM_NEWROUTE &&
                            record->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg)) &&
                            ((struct rtmsg*)NLMSG_DATA(record))->rtm_family == AF_INET,
                        "IPv4 route inventory");
            }
            records++;
        }
        require(!left, "complete netlink records");
    }
    require(0, "bounded dump datagrams");
    return 0;
}

int main(void) {
    setbuf(stdout, NULL);
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    int observer = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0 && observer >= 0, "inventory sockets");
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK}, own = {.nl_family = AF_NETLINK};
    require(!bind(fd, (struct sockaddr*)&own, sizeof(own)) &&
                !connect(fd, (struct sockaddr*)&kernel, sizeof(kernel)),
            "inventory bind and connect");
    socklen_t length = sizeof(own);
    require(!getsockname(fd, (struct sockaddr*)&own, &length) && own.nl_pid, "inventory port");
    unsigned sequence = 0;
    for (unsigned index = 0; index < 3; index++) {
        unsigned type = index == 0 ? RTM_GETLINK : index == 1 ? RTM_GETADDR : RTM_GETROUTE;
        const unsigned families[] = {AF_UNSPEC, AF_INET, AF_PACKET};
        for (unsigned item = 0; item < (index == 0 ? 3u : 1u); item++) {
            unsigned family = index == 0 ? families[item] : AF_INET;
            unsigned full = dump(fd, observer, type, family, 0, ++sequence, own.nl_pid);
            require(full == dump(fd, observer, type, family, 1, ++sequence, own.nl_pid),
                    "full and compact inventory agree");
        }
    }
    require(!close(observer) && !close(fd), "inventory close");
    puts("NETLINK_INVENTORY_PASS dumps=10 independent=names,flags,mtu,address");
    return 0;
}
