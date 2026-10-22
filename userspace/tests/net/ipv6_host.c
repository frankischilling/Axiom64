// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned sequence;
static unsigned indices[2];
static int packets[2];
static unsigned char macs[2][6];

static void check(int value, const char* reason) {
    if (!value) {
        fprintf(stderr, "IPV6_HOST_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static uint64_t now(void) {
    struct timespec value;
    check(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic clock");
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

static struct in6_addr address(unsigned lane, unsigned host, int local) {
    struct in6_addr result = IN6ADDR_ANY_INIT;
    if (local) {
        result.s6_addr[0] = 0xfe;
        result.s6_addr[1] = 0x80;
    } else {
        result.s6_addr[0] = 0x20;
        result.s6_addr[1] = 1;
        result.s6_addr[2] = 0x0d;
        result.s6_addr[3] = 0xb8;
        result.s6_addr[5] = lane + 1;
    }
    result.s6_addr[15] = host;
    return result;
}

static int control_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "netlink control socket");
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)), "netlink bind");
    int strict = 1;
    check(!setsockopt(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &strict, sizeof(strict)),
          "strict netlink dump filters");
    return fd;
}

static void send_request(int fd, struct nlmsghdr* header) {
    header->nlmsg_seq = ++sequence;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, header, header->nlmsg_len, 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              (ssize_t)header->nlmsg_len,
          "netlink request bytes");
}

static int acknowledge(int fd, struct nlmsghdr* header) {
    send_request(fd, header);
    unsigned char buffer[8192];
    ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
    check(length >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)), "netlink mutation result");
    struct nlmsghdr* response = (void*)buffer;
    check(response->nlmsg_seq == sequence && response->nlmsg_type == NLMSG_ERROR,
          "netlink mutation ownership");
    struct nlmsgerr result;
    memcpy(&result, NLMSG_DATA(response), sizeof(result));
    return result.error;
}

static int assign_prefix(int fd, unsigned lane, unsigned host, int local, int remove,
                         unsigned prefix, unsigned address_flags) {
    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr field;
        struct in6_addr value;
        struct rtattr flags_field;
        unsigned flags;
    } message = {0};

    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_type = remove ? RTM_DELADDR : RTM_NEWADDR;
    message.header.nlmsg_flags =
        NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_EXCL);
    message.address.ifa_family = AF_INET6;
    message.address.ifa_prefixlen = prefix;
    message.address.ifa_flags = address_flags;
    message.address.ifa_index = indices[lane];
    message.field.rta_len = sizeof(message.field) + sizeof(message.value);
    message.field.rta_type = IFA_ADDRESS;
    message.value = address(lane, host, local);
    message.flags_field = (struct rtattr){8, IFA_FLAGS};
    message.flags = address_flags;
    return acknowledge(fd, &message.header);
}

static int assign(int fd, unsigned lane, unsigned host, int local, int remove) {
    return assign_prefix(fd, lane, host, local, remove, 64, 0);
}

enum route_variant {
    ROUTE_ORDINARY,
    ROUTE_LOCAL_GATEWAY,
    ROUTE_OFFLINK_GATEWAY,
    ROUTE_OTHER_PREFIX,
    ROUTE_ADDRESS_PREFIX,
    ROUTE_FAILED_PREFIX,
    ROUTE_RETAINED_PREFIX,
    ROUTE_PREFIX_DELETE,
    ROUTE_DIRECT_256,
    ROUTE_DIRECT_LOW,
    ROUTE_DIRECT_HIGH,
    ROUTE_PREFIX_WILDCARD
};

static void attribute(void* buffer, size_t capacity, unsigned type, const void* data,
                      size_t length) {
    struct nlmsghdr* header = buffer;
    unsigned char* bytes = buffer;
    size_t at = NLMSG_ALIGN(header->nlmsg_len), size = RTA_ALIGN(RTA_LENGTH(length));
    check(at + size <= capacity, "bounded netlink attribute construction");
    struct rtattr field = {.rta_len = RTA_LENGTH(length), .rta_type = type};
    memcpy(bytes + at, &field, sizeof(field));
    memcpy(bytes + at + sizeof(field), data, length);
    header->nlmsg_len = at + size;
}

static int route_change(int fd, unsigned lane, int remove, enum route_variant variant) {
    struct {
        struct nlmsghdr header;
        struct rtmsg route;
        unsigned char attributes[80];
    } message = {0};

    message.header.nlmsg_len = NLMSG_LENGTH(sizeof(message.route));
    message.header.nlmsg_type = remove ? RTM_DELROUTE : RTM_NEWROUTE;
    message.header.nlmsg_flags =
        NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_EXCL);
    message.route.rtm_family = AF_INET6;
    message.route.rtm_dst_len = 64;
    message.route.rtm_table = RT_TABLE_MAIN;
    message.route.rtm_protocol = variant == ROUTE_PREFIX_DELETE ? RTPROT_KERNEL : 99;
    if (variant == ROUTE_PREFIX_WILDCARD)
        message.route.rtm_protocol = 0;
    message.route.rtm_type = RTN_UNICAST;
    struct in6_addr destination = address(50 + lane, 0, 0);
    struct in6_addr gateway = address(lane, 1, 1);
    unsigned metric = variant >= ROUTE_ADDRESS_PREFIX ? 256 : 5;
    if (variant == ROUTE_DIRECT_LOW)
        metric = 5;
    else if (variant == ROUTE_DIRECT_HIGH)
        metric = 512;
    if (variant == ROUTE_OTHER_PREFIX)
        destination = address(50 + (1 - lane), 0, 0);
    else if (variant == ROUTE_ADDRESS_PREFIX)
        destination = address(lane, 0, 0);
    else if (variant == ROUTE_FAILED_PREFIX) {
        destination = address(lane, 3, 0);
        message.route.rtm_dst_len = 128;
    } else if (variant >= ROUTE_RETAINED_PREFIX) {
        destination = address(lane, 0, 0);
        message.route.rtm_dst_len = 112;
    }
    if (variant == ROUTE_LOCAL_GATEWAY || variant == ROUTE_OFFLINK_GATEWAY)
        gateway = variant == ROUTE_LOCAL_GATEWAY ? address(lane, 2, 0) : address(99, 1, 0);
    attribute(&message, sizeof(message), RTA_DST, &destination, sizeof(destination));
    if (variant < ROUTE_PREFIX_DELETE)
        attribute(&message, sizeof(message), RTA_GATEWAY, &gateway, sizeof(gateway));
    attribute(&message, sizeof(message), RTA_OIF, &indices[lane], 4);
    // Omitted priority is a deletion wildcard.
    if (!remove)
        attribute(&message, sizeof(message), RTA_PRIORITY, &metric, 4);
    return acknowledge(fd, &message.header);
}

static unsigned route_count(int fd, unsigned lane) {
    struct {
        struct nlmsghdr header;
        struct rtmsg route;
        struct rtattr field;
        unsigned interface;
    } request = {0};

    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.route.rtm_family = AF_INET6;
    request.route.rtm_table = RT_TABLE_MAIN;
    request.route.rtm_protocol = 99;
    request.field = (struct rtattr){8, RTA_OIF};
    request.interface = indices[lane];
    send_request(fd, &request.header);
    unsigned count = 0;
    for (;;) {
        unsigned char buffer[8192];
        int length = recv(fd, buffer, sizeof(buffer), 0);
        check(length > 0, "actual IPv6 route dump");
        for (struct nlmsghdr* header = (void*)buffer; NLMSG_OK(header, length);
             header = NLMSG_NEXT(header, length)) {
            check(header->nlmsg_seq == sequence, "route dump sequence");
            if (header->nlmsg_type == NLMSG_DONE)
                return count;
            check(header->nlmsg_type == RTM_NEWROUTE &&
                      header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg)),
                  "route dump message");
            struct rtmsg* value = NLMSG_DATA(header);
            check(value->rtm_family == AF_INET6 && value->rtm_dst_len == 64 &&
                      value->rtm_protocol == 99 && value->rtm_table == RT_TABLE_MAIN,
                  "route dump header");
            struct in6_addr destination = address(50 + lane, 0, 0);
            struct in6_addr gateway = address(lane, 1, 1);
            unsigned seen = 0;
            int remaining = header->nlmsg_len - NLMSG_LENGTH(sizeof(*value));
            for (struct rtattr* field = RTM_RTA(value); RTA_OK(field, remaining);
                 field = RTA_NEXT(field, remaining)) {
                if (field->rta_type == RTA_DST || field->rta_type == RTA_GATEWAY) {
                    check(RTA_PAYLOAD(field) == 16 &&
                              !memcmp(RTA_DATA(field),
                                      field->rta_type == RTA_DST ? &destination : &gateway, 16),
                          "route address round trip");
                    seen |= field->rta_type == RTA_DST ? 1 : 2;
                } else if (field->rta_type == RTA_OIF || field->rta_type == RTA_PRIORITY) {
                    unsigned number;
                    check(RTA_PAYLOAD(field) == 4, "route scalar length");
                    memcpy(&number, RTA_DATA(field), 4);
                    check(number == (field->rta_type == RTA_OIF ? indices[lane] : 5),
                          "route interface and metric round trip");
                    seen |= field->rta_type == RTA_OIF ? 4 : 8;
                }
            }
            check(!remaining && seen == 15, "complete filtered route record");
            count++;
        }
        check(!length, "route dump datagram bounds");
    }
}

static int local_route_present(int fd, unsigned lane, const struct in6_addr* wanted) {
    struct {
        struct nlmsghdr header;
        struct rtmsg route;
        struct rtattr field;
        unsigned interface;
    } request = {0};

    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.route.rtm_family = AF_INET6;
    request.route.rtm_table = RT_TABLE_LOCAL;
    request.field = (struct rtattr){8, RTA_OIF};
    request.interface = indices[lane];
    send_request(fd, &request.header);
    unsigned found = 0;
    uint64_t began = now();
    for (;;) {
        struct pollfd poller = {.fd = fd, .events = POLLIN};
        int ready = poll(&poller, 1, 100);
        check(ready >= 0 && now() - began < 10000000000ULL, "bounded local route dump");
        if (!ready)
            continue;
        _Alignas(8) unsigned char buffer[8192];
        int length = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        check(length > 0, "actual local route dump");
        for (struct nlmsghdr* header = (void*)buffer; NLMSG_OK(header, length);
             header = NLMSG_NEXT(header, length)) {
            check(header->nlmsg_seq == sequence, "local route sequence");
            if (header->nlmsg_type == NLMSG_DONE) {
                int status;
                check(header->nlmsg_len >= NLMSG_LENGTH(sizeof(status)), "local route completion");
                memcpy(&status, NLMSG_DATA(header), sizeof(status));
                check(!status && !(header->nlmsg_flags & NLM_F_DUMP_INTR),
                      "complete local route inventory");
                return found;
            }
            check(header->nlmsg_type == RTM_NEWROUTE &&
                      header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg)),
                  "local route record");
            struct rtmsg* route = NLMSG_DATA(header);
            unsigned index = 0, table = route->rtm_table, seen = 0;
            struct in6_addr destination = IN6ADDR_ANY_INIT;
            int remaining = RTM_PAYLOAD(header);
            for (struct rtattr* field = RTM_RTA(route); RTA_OK(field, remaining);
                 field = RTA_NEXT(field, remaining)) {
                unsigned bit = field->rta_type == RTA_DST     ? 1
                               : field->rta_type == RTA_OIF   ? 2
                               : field->rta_type == RTA_TABLE ? 4
                                                              : 0;
                if (!bit)
                    continue;
                check(!(seen & bit) && RTA_PAYLOAD(field) == (bit == 1 ? 16 : 4),
                      "local route attributes");
                seen |= bit;
                memcpy(bit == 1   ? (void*)&destination
                       : bit == 2 ? (void*)&index
                                  : (void*)&table,
                       RTA_DATA(field), bit == 1 ? 16 : 4);
            }
            check(!remaining, "local route attribute bounds");
            if (route->rtm_type == RTN_LOCAL && route->rtm_dst_len == 128 &&
                !memcmp(&destination, wanted, sizeof(destination))) {
                check(route->rtm_family == AF_INET6 && table == RT_TABLE_LOCAL &&
                          route->rtm_protocol == RTPROT_KERNEL && index == indices[lane] &&
                          (seen & 3) == 3 && !found++,
                      "single owned local destination route");
            }
        }
        check(!length, "local route datagram bounds");
    }
}

static void wait_local_route(int fd, unsigned lane) {
    struct in6_addr wanted = address(lane, 2, 0);
    uint64_t began = now();
    unsigned polls = 0;
    while (!local_route_present(fd, lane, &wanted)) {
        check(now() - began < 10000000000ULL, "finite local route publication");
        struct timespec pause = {0, 10000000};
        check(!nanosleep(&pause, NULL), "local route observation wait");
        polls++;
    }
    printf("IPV6_HOST_LOCAL_ROUTE_PASS lane=%u polls=%u elapsed_ns=%llu\n", lane, polls,
           (unsigned long long)(now() - began));
}

static unsigned flags(int fd, unsigned lane, unsigned host, int local, unsigned prefix) {
    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
    } request = {0};

    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = RTM_GETADDR;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.address.ifa_family = AF_INET6;
    send_request(fd, &request.header);
    struct in6_addr wanted = address(lane, host, local);
    unsigned result = 0xffffffff;
    for (;;) {
        unsigned char buffer[8192];
        int length = recv(fd, buffer, sizeof(buffer), 0);
        check(length > 0, "actual IPv6 address dump");
        for (struct nlmsghdr* header = (void*)buffer; NLMSG_OK(header, length);
             header = NLMSG_NEXT(header, length)) {
            check(header->nlmsg_seq == sequence, "address dump sequence");
            if (header->nlmsg_type == NLMSG_DONE)
                return result;
            check(header->nlmsg_type == RTM_NEWADDR, "address dump message");
            struct ifaddrmsg* value = NLMSG_DATA(header);
            if (value->ifa_family != AF_INET6 || value->ifa_index != indices[lane])
                continue;
            int remaining = header->nlmsg_len - NLMSG_LENGTH(sizeof(*value));
            for (struct rtattr* field = IFA_RTA(value); RTA_OK(field, remaining);
                 field = RTA_NEXT(field, remaining))
                if (field->rta_type == IFA_ADDRESS && RTA_PAYLOAD(field) == 16 &&
                    !memcmp(RTA_DATA(field), &wanted, 16)) {
                    check(value->ifa_prefixlen == prefix, "actual address prefix inventory");
                    result = value->ifa_flags;
                }
        }
    }
}

static void prefix_lifecycle(int fd, unsigned lane) {
    check(!assign_prefix(fd, lane, 9, 0, 0, 112, IFA_F_NODAD | IFA_F_NOPREFIXROUTE),
          "configure prefixless address");
    check(!route_change(fd, lane, 0, ROUTE_RETAINED_PREFIX) &&
              !route_change(fd, lane, 1, ROUTE_RETAINED_PREFIX),
          "prefixless address does not create a route");
    check(!assign_prefix(fd, lane, 8, 0, 0, 112, IFA_F_NODAD), "create prefix owner");
    check(route_change(fd, lane, 0, ROUTE_RETAINED_PREFIX) == -EEXIST,
          "owned prefix participates in route exclusivity");
    check(!assign_prefix(fd, lane, 8, 0, 1, 112, 0) &&
              route_change(fd, lane, 0, ROUTE_RETAINED_PREFIX) == -EEXIST,
          "prefixless companion retains prefix ownership");
    check(!assign_prefix(fd, lane, 9, 0, 1, 112, 0) &&
              route_change(fd, lane, 0, ROUTE_RETAINED_PREFIX) == -EEXIST,
          "prefixless deletion preserves managed prefix");
    check(!route_change(fd, lane, 1, ROUTE_PREFIX_DELETE) &&
              !route_change(fd, lane, 0, ROUTE_RETAINED_PREFIX) &&
              !route_change(fd, lane, 1, ROUTE_RETAINED_PREFIX),
          "explicit retained prefix cleanup");
}

static void expect_prefix_routes(int fd, unsigned lane, unsigned manual_metric, int kernel) {
    struct {
        struct nlmsghdr header;
        struct rtmsg route;
        struct rtattr field;
        unsigned interface;
    } request = {0};

    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.route.rtm_family = AF_INET6;
    request.route.rtm_table = RT_TABLE_MAIN;
    request.field = (struct rtattr){8, RTA_OIF};
    request.interface = indices[lane];
    send_request(fd, &request.header);
    unsigned found_manual = 0, found_kernel = 0;
    for (;;) {
        unsigned char buffer[8192];
        int length = recv(fd, buffer, sizeof(buffer), 0);
        check(length > 0, "prefix route dump");
        for (struct nlmsghdr* header = (void*)buffer; NLMSG_OK(header, length);
             header = NLMSG_NEXT(header, length)) {
            check(header->nlmsg_seq == sequence, "prefix route sequence");
            if (header->nlmsg_type == NLMSG_DONE) {
                check(found_manual == !!manual_metric && found_kernel == !!kernel,
                      "exact manual and connected prefix inventory");
                return;
            }
            check(header->nlmsg_type == RTM_NEWROUTE &&
                      header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg)),
                  "prefix route message");
            struct rtmsg* value = NLMSG_DATA(header);
            if (value->rtm_dst_len != 112)
                continue;
            check(value->rtm_family == AF_INET6 && value->rtm_table == RT_TABLE_MAIN &&
                      (value->rtm_protocol == 99 || value->rtm_protocol == RTPROT_KERNEL),
                  "prefix route header");
            struct in6_addr destination = address(lane, 0, 0);
            unsigned seen = 0, metric = 0;
            int remaining = header->nlmsg_len - NLMSG_LENGTH(sizeof(*value));
            for (struct rtattr* field = RTM_RTA(value); RTA_OK(field, remaining);
                 field = RTA_NEXT(field, remaining)) {
                if (field->rta_type == RTA_DST) {
                    check(RTA_PAYLOAD(field) == 16 && !memcmp(RTA_DATA(field), &destination, 16),
                          "prefix route destination");
                    seen |= 1;
                } else if (field->rta_type == RTA_OIF) {
                    unsigned index;
                    check(RTA_PAYLOAD(field) == 4, "prefix route interface length");
                    memcpy(&index, RTA_DATA(field), 4);
                    check(index == indices[lane], "prefix route interface filter");
                    seen |= 2;
                } else if (field->rta_type == RTA_PRIORITY) {
                    check(RTA_PAYLOAD(field) == 4, "prefix route metric length");
                    memcpy(&metric, RTA_DATA(field), 4);
                    seen |= 4;
                } else
                    check(field->rta_type != RTA_GATEWAY, "direct prefix has no gateway");
            }
            check(!remaining && seen == 7, "complete prefix route record");
            if (value->rtm_protocol == RTPROT_KERNEL) {
                check(kernel && metric == 256 && !found_kernel++, "single connected prefix");
            } else
                check(manual_metric && metric == manual_metric && !found_manual++,
                      "single manual prefix");
        }
        check(!length, "prefix route datagram bounds");
    }
}

static void prefix_route_order(int fd, unsigned lane) {
    check(!route_change(fd, lane, 0, ROUTE_DIRECT_256) &&
              !assign_prefix(fd, lane, 8, 0, 0, 112, IFA_F_NODAD),
          "manual route precedes prefix address");
    expect_prefix_routes(fd, lane, 256, 0);
    check(!assign_prefix(fd, lane, 8, 0, 1, 112, 0), "last address consumes direct manual route");
    expect_prefix_routes(fd, lane, 0, 0);

    check(!route_change(fd, lane, 0, ROUTE_DIRECT_LOW) &&
              !assign_prefix(fd, lane, 8, 0, 0, 112, IFA_F_NODAD),
          "manual route below connected metric");
    expect_prefix_routes(fd, lane, 5, 1);
    check(!assign_prefix(fd, lane, 8, 0, 1, 112, 0), "last address consumes lowest direct metric");
    expect_prefix_routes(fd, lane, 0, 1);
    check(!route_change(fd, lane, 1, ROUTE_PREFIX_WILDCARD), "remove retained connected prefix");
    expect_prefix_routes(fd, lane, 0, 0);

    check(!route_change(fd, lane, 0, ROUTE_DIRECT_HIGH) &&
              !assign_prefix(fd, lane, 8, 0, 0, 112, IFA_F_NODAD),
          "manual route above connected metric");
    expect_prefix_routes(fd, lane, 512, 1);
    check(!route_change(fd, lane, 1, ROUTE_PREFIX_WILDCARD), "wildcard consumes lowest metric");
    expect_prefix_routes(fd, lane, 512, 0);
    check(!assign_prefix(fd, lane, 8, 0, 1, 112, 0), "remaining direct route address cleanup");
    expect_prefix_routes(fd, lane, 0, 0);
    printf("IPV6_HOST_PREFIX_ORDER_PASS lane=%u scenarios=3\n", lane);
}

static void wait_address(int fd, unsigned lane, unsigned host, int local, int duplicate,
                         unsigned prefix) {
    uint64_t began = now();
    for (;;) {
        unsigned value = flags(fd, lane, host, local, prefix);
        check(value != 0xffffffff, "configured IPv6 address stays inventoried");
        if (duplicate ? !!(value & IFA_F_DADFAILED)
                      : !(value & (IFA_F_TENTATIVE | IFA_F_DADFAILED)))
            return;
        check(now() - began < 10000000000ULL, "finite DAD completion");
        struct timespec pause = {0, 10000000};
        check(!nanosleep(&pause, NULL), "DAD observation wait");
    }
}

static void barrier(unsigned lane, unsigned phase) {
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = 0x88;
    frame[13] = 0xb6;
    memcpy(frame + 14, "IP6H", 4);
    frame[18] = lane;
    frame[19] = phase;
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(0x88b6),
                                 .sll_ifindex = indices[lane],
                                 .sll_halen = 6};
    memcpy(target.sll_addr, frame, 6);
    check(sendto(packets[lane], frame, sizeof(frame), 0, (struct sockaddr*)&target,
                 sizeof(target)) == sizeof(frame),
          "Ethernet phase request");
    uint64_t began = now();
    for (;;) {
        struct pollfd poller = {.fd = packets[lane], .events = POLLIN};
        check(poll(&poller, 1, 100) >= 0, "Ethernet phase poll");
        unsigned char reply[1600];
        ssize_t length = recv(packets[lane], reply, sizeof(reply), MSG_DONTWAIT);
        if (length >= 21 && !memcmp(reply, macs[lane], 6) && reply[12] == 0x88 &&
            reply[13] == 0xb6 && !memcmp(reply + 14, "IP6H", 4) && reply[18] == lane &&
            reply[19] == phase && reply[20] == 1)
            break;
        check(now() - began < 10000000000ULL, "finite independent peer acknowledgement");
    }
    printf("IPV6_HOST_PHASE_PASS lane=%u phase=%u\n", lane, phase);
}

void ipv6_address_lifetimes(void);

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int fd = control_socket();
    int links = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(links >= 0, "interface control socket");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(links, SIOCGIFINDEX, &request), "actual interface index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(links, SIOCGIFHWADDR, &request), "actual interface MAC");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        request.ifr_flags = IFF_UP;
        check(!ioctl(links, SIOCSIFFLAGS, &request), "interface up");
        packets[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(3));
        check(packets[lane] >= 0, "Ethernet observation socket");
        struct sockaddr_ll target = {
            .sll_family = AF_PACKET, .sll_protocol = htons(3), .sll_ifindex = indices[lane]};
        check(!bind(packets[lane], (struct sockaddr*)&target, sizeof(target)), "Ethernet binding");
    }
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, 0);
    uint64_t began = now();
    for (unsigned lane = 0; lane < 2; lane++) {
        check(!assign(fd, lane, 2, 1, 0), "link-local address add");
        check(!assign(fd, lane, 2, 0, 0), "global address add");
        check(flags(fd, lane, 2, 0, 64) & IFA_F_TENTATIVE, "observe actual tentative address");
        check(route_change(fd, lane, 0, ROUTE_ADDRESS_PREFIX) == -EEXIST,
              "tentative prefix already owns its route");
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        wait_address(fd, lane, 2, 1, 0, 64);
        wait_address(fd, lane, 2, 0, 0, 64);
    }
    uint64_t elapsed = now() - began;
    check(elapsed >= 1000000000ULL, "complete DAD retransmit interval");
    printf("IPV6_HOST_DAD_PASS elapsed_ns=%llu\n", (unsigned long long)elapsed);
    for (unsigned lane = 0; lane < 2; lane++)
        check(route_change(fd, lane, 0, ROUTE_LOCAL_GATEWAY) == -EINVAL &&
                  route_change(fd, lane, 0, ROUTE_OFFLINK_GATEWAY) == -EHOSTUNREACH,
              "local and unreachable IPv6 gateways rejected");
    for (unsigned lane = 0; lane < 2; lane++)
        check(!route_change(fd, lane, 0, ROUTE_ORDINARY) &&
                  route_change(fd, lane, 0, ROUTE_ORDINARY) == -EEXIST,
              "exclusive IPv6 route creation");
    for (unsigned lane = 0; lane < 2; lane++)
        check(route_count(fd, lane) == 1, "interface-filtered IPv6 route inventory");
    check(route_change(fd, 1, 0, ROUTE_OTHER_PREFIX) == -EEXIST,
          "exclusive routes conflict across interfaces");
    for (unsigned lane = 0; lane < 2; lane++)
        check(!route_change(fd, lane, 1, ROUTE_ORDINARY) &&
                  route_change(fd, lane, 1, ROUTE_ORDINARY) == -ESRCH && !route_count(fd, lane),
              "IPv6 route deletion and absence");
    puts("IPV6_HOST_ROUTES_PASS adapters=2 filtered=1");
    for (unsigned lane = 0; lane < 2; lane++) {
        prefix_lifecycle(fd, lane);
        prefix_route_order(fd, lane);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        barrier(lane, 1);
        barrier(lane, 2);
        barrier(lane, 3);
        check(!assign_prefix(fd, lane, 3, 0, 0, 128, 0), "duplicate candidate add");
        wait_address(fd, lane, 3, 0, 1, 128);
        check(route_change(fd, lane, 0, ROUTE_FAILED_PREFIX) == -EEXIST,
              "failed permanent address retains prefix ownership");
        barrier(lane, 4);
        check(!assign_prefix(fd, lane, 3, 0, 1, 128, 0), "failed duplicate remove");
        check(!assign(fd, lane, 2, 0, 1) && !assign_prefix(fd, lane, 2, 0, 0, 128, IFA_F_NODAD),
              "configure direct ND host address");
        check(!(flags(fd, lane, 2, 0, 128) & (IFA_F_TENTATIVE | IFA_F_DADFAILED)),
              "direct ND host address is ready");
        wait_local_route(fd, lane);
        barrier(lane, 5);
        printf("IPV6_HOST_DIRECT_ND_PASS lane=%u prefix=128\n", lane);
        check(!assign_prefix(fd, lane, 2, 0, 1, 128, 0) &&
                  !assign_prefix(fd, lane, 2, 0, 0, 64, IFA_F_NODAD),
              "restore connected IPv6 prefix");
    }
    puts("IPV6_HOST_PREFIX_PASS adapters=2 tentative=1 failed=1 retained=1");
    pid_t child = fork();
    check(child >= 0, "permission child");
    if (!child) {
        check(!setuid(65534), "drop network administration");
        check(assign(fd, 0, 7, 0, 0) == -EPERM, "unprivileged IPv6 mutation denied");
        check(route_change(fd, 0, 0, ROUTE_ORDINARY) == -EPERM, "unprivileged IPv6 route denied");
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "permission child result");
    for (unsigned lane = 0; lane < 2; lane++) {
        check(!assign(fd, lane, 2, 0, 1) && !assign(fd, lane, 2, 1, 1), "address cleanup");
        check(flags(fd, lane, 2, 0, 64) == 0xffffffff, "removed address absent");
        close(packets[lane]);
    }
    close(fd);
    close(links);
    ipv6_address_lifetimes();
    puts("IPV6_HOST_PASS nics=2 phases_each=5 DAD=1 duplicate=1 permissions=1");
}
