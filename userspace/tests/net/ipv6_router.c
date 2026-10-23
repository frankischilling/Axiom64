// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_ROUTER"
#define IPV6_BARRIER_PROTOCOL 0x88bf
#define IPV6_BARRIER_MAGIC "IP6R"
#include "ipv6_fixture.h"
#include <fcntl.h>

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

static struct in6_addr link_address(unsigned lane) {
    struct in6_addr value = prefix_address(lane, 0, 1);
    memset(value.s6_addr, 0, 8);
    value.s6_addr[0] = 0xfe;
    value.s6_addr[1] = 0x80;
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

static const struct address_record* find(const struct inventory* inventory,
                                         struct in6_addr address) {
    for (unsigned at = 0; at < inventory->address_count; at++)
        if (!memcmp(&inventory->addresses[at].address, &address, 16))
            return &inventory->addresses[at];
    return NULL;
}

static void report(unsigned lane, const struct inventory* inventory) {
    printf("IPV6_ROUTER_INVENTORY lane=%u addresses=%u routes=%u\n", lane, inventory->address_count,
           inventory->route_count);
    for (unsigned at = 0; at < inventory->address_count; at++) {
        const struct address_record* value = inventory->addresses + at;
        char text[INET6_ADDRSTRLEN];
        check(inet_ntop(AF_INET6, &value->address, text, sizeof(text)) != NULL, "address format");
        printf("IPV6_ROUTER_ADDRESS lane=%u address=%s flags=%x preferred=%u valid=%u\n", lane,
               text, value->flags, value->preferred, value->valid);
    }
    for (unsigned at = 0; at < inventory->route_count; at++) {
        const struct route_record* value = inventory->routes + at;
        char destination[INET6_ADDRSTRLEN], gateway[INET6_ADDRSTRLEN];
        check(inet_ntop(AF_INET6, &value->destination, destination, sizeof(destination)) != NULL &&
                  inet_ntop(AF_INET6, &value->gateway, gateway, sizeof(gateway)) != NULL,
              "route format");
        printf("IPV6_ROUTER_ROUTE lane=%u destination=%s/%u gateway=%s metric=%u protocol=%u "
               "expires=%d\n",
               lane, destination, value->prefix, gateway, value->metric, value->protocol,
               value->expires);
    }
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

static struct inventory wait_addresses(unsigned lane, int present) {
    uint64_t began = now();
    for (;;) {
        struct inventory inventory = snapshot(lane);
        const struct address_record* main = find(&inventory, prefix_address(lane, 1, 1));
        const struct address_record* autonomous = find(&inventory, prefix_address(lane, 3, 1));
        if (present ? main && autonomous && !((main->flags | autonomous->flags) & 0x48)
                    : !main && !autonomous)
            return inventory;
        check(now() - began < (present ? 5000000000ULL : 12000000000ULL),
              present ? "generated addresses complete DAD" : "finite generated addresses expire");
        struct timespec delay = {0, 20000000};
        nanosleep(&delay, NULL);
    }
}

static void probe(unsigned lane, unsigned phase, int mtu) {
    int fd = create(SOCK_DGRAM);
    char name[40] = {0};
    snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, sizeof(name)),
          "router bound interface");
    struct sockaddr_in6 target = {.sin6_family = AF_INET6, .sin6_port = htons(47001)};
    struct sockaddr_in6 source = {.sin6_family = AF_INET6, .sin6_port = htons(47000 + lane)};
    source.sin6_addr = phase == 2 ? link_address(lane) : prefix_address(lane, 1, 1);
    if (phase == 2)
        source.sin6_scope_id = indices[lane];
    bind_address(fd, source);
    if (phase == 2) {
        inet_pton(AF_INET6, "fe80::42", &target.sin6_addr);
        target.sin6_scope_id = indices[lane];
    } else if (phase == 3)
        inet_pton(AF_INET6, "2001:db8:ffff::42", &target.sin6_addr);
    else {
        target.sin6_addr = prefix_address(lane, phase == 5 ? 1 : 2, 0);
        target.sin6_addr.s6_addr[15] = phase == 5 ? 0x44 : 0x42;
    }
    connect_address(fd, target);
    check(get(fd, IPPROTO_IPV6, IPV6_MTU) == mtu, "learned IPv6 path MTU");
    option(fd, IPPROTO_IPV6, IPV6_DONTFRAG, 1);
    unsigned char large[1500] = {0};
    errno = 0;
    check(send(fd, large, mtu - 47, 0) == -1 && errno == EMSGSIZE,
          "learned MTU rejects oversized UDP");
    unsigned char bytes[16] = {'R', 'A', 'T', 'R', lane, phase};
    for (unsigned at = 6; at < sizeof(bytes); at++)
        bytes[at] = at * 7 + phase;
    check(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "generated-source UDP output");
    unsigned char reply[16];
    receive_exact(fd, reply, sizeof(reply));
    check(!memcmp(bytes, reply, sizeof(bytes)), "exact generated-source UDP reply");
    close(fd);
}

static void manual_address(unsigned lane, int remove) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "manual replacement netlink socket");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr address_field;
        struct in6_addr value;
        struct rtattr cache_field;
        struct ifa_cacheinfo cache;
    } request = {0};

    request.header = (struct nlmsghdr){
        sizeof(request), remove ? RTM_DELADDR : RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_REPLACE), 1, 0};
    request.address = (struct ifaddrmsg){AF_INET6, 64, IFA_F_NODAD, 0, indices[lane]};
    request.address_field = (struct rtattr){20, IFA_ADDRESS};
    request.value = prefix_address(lane, 1, 1);
    request.cache_field = (struct rtattr){20, IFA_CACHEINFO};
    request.cache.ifa_prefered = request.cache.ifa_valid = UINT32_MAX;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &request, sizeof(request), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(request),
          "manual replacement request");
    unsigned char response[256];
    readable(fd, POLLIN);
    ssize_t size = recv(fd, response, sizeof(response), 0);
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "manual replacement acknowledgment");
    struct nlmsgerr result;
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)response), sizeof(result));
    check(!result.error, "manual replacement result");
    close(fd);
}

static void replacement_check(unsigned lane, const char* phase, unsigned flags, unsigned preferred,
                              unsigned valid) {
    uint64_t began = now();
    int waited = 0;
    for (;;) {
        struct inventory inventory = snapshot(lane);
        const struct address_record* address = find(&inventory, prefix_address(lane, 1, 1));
        check(address != NULL, "manual replacement address remains assigned");
        unsigned count = routes(&inventory, prefix_address(lane, 1, 0), 64), permanent = 0;
        struct in6_addr empty = {0}, prefix = prefix_address(lane, 1, 0);
        for (unsigned at = 0; at < inventory.route_count; at++) {
            const struct route_record* route = inventory.routes + at;
            permanent += route->prefix == 64 && !memcmp(&route->destination, &prefix, 16) &&
                         !memcmp(&route->gateway, &empty, 16) && route->protocol == RTPROT_KERNEL &&
                         route->metric == 256 && !route->expires;
        }
        int metadata = address->valid <= valid &&
                       address->valid >= (valid == UINT32_MAX ? valid : valid - 2) &&
                       address->preferred <= preferred &&
                       address->preferred >=
                           (preferred > 2 && preferred != UINT32_MAX ? preferred - 2 : preferred) &&
                       count == 1 && permanent == 1;
        if (metadata && address->flags == flags) {
            printf("IPV6_ROUTER_REPLACEMENT lane=%u phase=%s flags=%x preferred=%u valid=%u "
                   "prefix_routes=%u prefix_permanent=%u\n",
                   lane, phase, address->flags, address->preferred, address->valid, count,
                   permanent);
            report(lane, &inventory);
            return;
        }
        // Linux can publish a zero preferred cache before its deferred
        // deprecation flag update. Every other field must already match.
        check(
            metadata && strcmp(phase, "replaced") && strcmp(phase, "readded") &&
                (address->flags ^ flags) == IFA_F_DEPRECATED && now() - began < 1000000000ULL,
            "replacement keeps Linux metadata, protected lifetimes and permanent connected prefix");
        if (!waited)
            printf("IPV6_ROUTER_DEPRECATION_WAIT lane=%u phase=%s flags=%x preferred=%u valid=%u\n",
                   lane, phase, address->flags, address->preferred, address->valid);
        waited = 1;
        struct timespec delay = {0, 20000000};
        check(!nanosleep(&delay, NULL), "bounded Linux deprecation-flag observation");
    }
}

static void expired_default(unsigned lane) {
    int fd = create(SOCK_DGRAM);
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "expired-router bound interface");
    struct sockaddr_in6 target = {.sin6_family = AF_INET6, .sin6_port = htons(47001)};
    inet_pton(AF_INET6, "2001:db8:ffff::42", &target.sin6_addr);
    errno = 0;
    check(connect(fd, (const struct sockaddr*)&target, sizeof(target)) == -1 &&
              errno == ENETUNREACH,
          "expired default cannot supply a fresh socket route");
    close(fd);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    scalar("all", "disable_ipv6", 1);
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(control >= 0, "router interface control");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(control, SIOCGIFINDEX, &request), "router interface index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(control, SIOCGIFHWADDR, &request), "router interface MAC");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        request.ifr_flags = IFF_UP;
        check(!ioctl(control, SIOCSIFFLAGS, &request), "router interface up");
        scalar(request.ifr_name, "addr_gen_mode", 0);
        scalar(request.ifr_name, "accept_ra", 1);
        scalar(request.ifr_name, "autoconf", 1);
        scalar(request.ifr_name, "router_solicitations", -1);
        scalar(request.ifr_name, "dad_transmits", 1);
        scalar(request.ifr_name, "enhanced_dad", 1);
        packets[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(3));
        check(packets[lane] >= 0, "router Ethernet control socket");
        struct sockaddr_ll binding = {
            .sll_family = AF_PACKET, .sll_protocol = htons(3), .sll_ifindex = indices[lane]};
        check(!bind(packets[lane], (struct sockaddr*)&binding, sizeof(binding)),
              "router Ethernet binding");
        barrier(lane, 0);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        scalar(name, "disable_ipv6", 0);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        barrier(lane, 1);
        struct inventory inventory = snapshot(lane);
        const struct address_record* link = find(&inventory, link_address(lane));
        report(lane, &inventory);
        check(link && !(link->flags & 0x48) && inventory.address_count == 1 &&
                  inventory.route_count == 1,
              "invalid advertisements leave only the ready link-local address and route");
        barrier(lane, 2);
        probe(lane, 2, 1400);
    }
    struct timespec interval = {5, 0};
    check(!nanosleep(&interval, NULL), "real zero-lifetime solicitation observation");
    uint64_t advertised[2];
    for (unsigned lane = 0; lane < 2; lane++) {
        barrier(lane, 3);
        advertised[lane] = now();
        struct inventory inventory = wait_addresses(lane, 1);
        report(lane, &inventory);
        struct in6_addr empty = {0};
        check(inventory.address_count == 3 && routes(&inventory, empty, 0) == 1 &&
                  routes(&inventory, prefix_address(lane, 1, 0), 64) == 1 &&
                  routes(&inventory, prefix_address(lane, 2, 0), 64) == 1 &&
                  !routes(&inventory, prefix_address(lane, 3, 0), 64) &&
                  !routes(&inventory, prefix_address(lane, 4, 0), 64),
              "independent autonomous and on-link prefix flags");
        struct in6_addr router;
        check(inet_pton(AF_INET6, "fe80::42", &router) == 1, "router address format");
        for (unsigned at = 0; at < inventory.route_count; at++) {
            const struct route_record* route = inventory.routes + at;
            if (!route->prefix)
                check(route->protocol == RTPROT_RA && route->metric == 1024 &&
                          !memcmp(&route->gateway, &router, 16),
                      "default-router dump metadata");
            else
                check(route->protocol == RTPROT_KERNEL && route->metric == 256 &&
                          !memcmp(&route->gateway, &empty, 16),
                      "on-link prefix dump metadata");
        }
        probe(lane, 3, 1300);
        probe(lane, 4, 1300);
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(control, SIOCGIFMTU, &request) && request.ifr_mtu == 1500,
              "IPv6 advertisement keeps the physical IPv4 MTU");
        barrier(lane, 4);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        for (;;) {
            struct inventory inventory = snapshot(lane);
            const struct address_record* address = find(&inventory, prefix_address(lane, 1, 1));
            struct in6_addr empty = {0};
            check(address && address->valid, "finite address remains through preferred expiry");
            if (!address->preferred && (address->flags & IFA_F_DEPRECATED) &&
                !routes(&inventory, empty, 0)) {
                report(lane, &inventory);
                expired_default(lane);
                break;
            }
            if (now() - advertised[lane] >= 7000000000ULL)
                report(lane, &inventory);
            check(now() - advertised[lane] < 7000000000ULL, "preferred and default-router expiry");
            struct timespec delay = {0, 20000000};
            nanosleep(&delay, NULL);
        }
        barrier(lane, 5);
        struct inventory inventory = snapshot(lane);
        const struct address_record* address = find(&inventory, prefix_address(lane, 1, 1));
        check(address && !address->preferred && address->valid && address->valid <= 8 &&
                  !routes(&inventory, prefix_address(lane, 1, 0), 64) &&
                  !routes(&inventory, prefix_address(lane, 2, 0), 64),
              "zero PIO withdraws on-link routes while retaining protected finite addresses");
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        struct inventory inventory = wait_addresses(lane, 0);
        check(inventory.address_count == 1, "finite SLAAC ownership expires");
        barrier(lane, 6);
        wait_addresses(lane, 1);
        barrier(lane, 7);
        inventory = snapshot(lane);
        const struct address_record* address = find(&inventory, prefix_address(lane, 1, 1));
        check(address && !address->preferred && address->valid >= 7198 && address->valid <= 7200,
              "unauthenticated reduction retains two-hour valid lifetime");
        barrier(lane, 8);
        barrier(lane, 9);
        inventory = snapshot(lane);
        printf("IPV6_ROUTER_MAC_POLICY lane=%u installed=%u\n", lane,
               find(&inventory, prefix_address(lane, 107, 1)) != NULL);
        barrier(lane, 10);
        manual_address(lane, 0);
        replacement_check(lane, "replaced", 0x82, UINT32_MAX, UINT32_MAX);
        barrier(lane, 11);
        replacement_check(lane, "zero", 0xa2, 0, 7200);
        barrier(lane, 12);
        replacement_check(lane, "finite", 0x82, 60, 7200);
        barrier(lane, 13);
        manual_address(lane, 1);
        manual_address(lane, 0);
        replacement_check(lane, "readded", 0x82, UINT32_MAX, UINT32_MAX);
        barrier(lane, 14);
        replacement_check(lane, "readd-zero", 0xa2, 0, 7200);
        barrier(lane, 15);
        replacement_check(lane, "readd-finite", 0x82, 60, 7200);
        barrier(lane, 16);
    }
    // Install distinct per-interface retry values before either resolution.
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, 17);
    for (unsigned lane = 0; lane < 2; lane++) {
        probe(lane, 5, 1300);
        barrier(lane, 18);
    }
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, 19);
    for (unsigned phase = 20; phase <= 22; phase++)
        for (unsigned lane = 0; lane < 2; lane++)
            barrier(lane, phase);
    puts("IPV6_ROUTER_PASS adapters=2 invalid_each=8 mac_policy_each=1 flags=4 finite_seconds=8 "
         "protection_seconds=7200 replacement_each=6 retransmit_milliseconds=2000,3000 "
         "routed_reply_each=2");
    close(control);
    return 0;
}
