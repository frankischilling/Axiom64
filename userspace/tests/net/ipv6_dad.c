// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_DAD"
#define IPV6_BARRIER_PROTOCOL 0x88c2
#define IPV6_BARRIER_MAGIC "IP6D"
#include "ipv6_fixture.h"
#include <fcntl.h>
#include "ipv6_dad_inventory.h"

static unsigned phases[2];
static int retain_exhausted_routes;

static void pause_poll(void) {
    struct timespec delay = {0, 20000000};
    check(!nanosleep(&delay, NULL), "DAD inventory polling");
}

static void control(unsigned lane, unsigned kind, unsigned scenario, unsigned trial,
                    const struct address_record* value) {
    unsigned phase = phases[lane]++;
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = IPV6_BARRIER_PROTOCOL >> 8;
    frame[13] = IPV6_BARRIER_PROTOCOL & 255;
    memcpy(frame + 14, IPV6_BARRIER_MAGIC, 4);
    frame[18] = lane;
    frame[19] = phase;
    frame[20] = kind;
    frame[21] = scenario;
    frame[22] = trial;
    frame[23] = !kind && retain_exhausted_routes;
    if (value) {
        uint32_t flags = htonl(value->flags), preferred = htonl(value->preferred);
        uint32_t valid = htonl(value->valid);
        memcpy(frame + 24, &flags, 4);
        memcpy(frame + 28, &preferred, 4);
        memcpy(frame + 32, &valid, 4);
        memcpy(frame + 36, &value->address, 16);
    }
    uint64_t stamp = now();
    for (unsigned at = 0; at < 8; at++)
        frame[52 + at] = stamp >> (56 - at * 8);
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(IPV6_BARRIER_PROTOCOL),
                                 .sll_ifindex = indices[lane],
                                 .sll_halen = 6};
    memcpy(target.sll_addr, frame, 6);
    check(sendto(packets[lane], frame, sizeof(frame), 0, (struct sockaddr*)&target,
                 sizeof(target)) == sizeof(frame),
          "complete DAD observation barrier");
    uint64_t began = now();
    for (;;) {
        unsigned char reply[1600];
        struct pollfd item = {.fd = packets[lane], .events = POLLIN};
        check(poll(&item, 1, 100) >= 0, "DAD barrier readiness");
        ssize_t size = recv(packets[lane], reply, sizeof(reply), MSG_DONTWAIT);
        if (size == 60 && !memcmp(reply, macs[lane], 6) && !memcmp(reply + 6, frame, 6) &&
            !memcmp(reply + 12, frame + 12, 8) && reply[20] == 1)
            break;
        check(now() - began < 10000000000ULL, "finite DAD observation barrier");
    }
    printf("IPV6_DAD_CONTROL lane=%u phase=%u kind=%u scenario=%u trial=%u observed_ns=%llu\n",
           lane, phase, kind, scenario, trial, (unsigned long long)stamp);
}

static void controls(unsigned kind, unsigned scenario) {
    for (unsigned lane = 0; lane < 2; lane++)
        control(lane, kind, scenario, 0, NULL);
}

static void links_ready(unsigned stage) {
    static struct in6_addr stable[2];
    unsigned complete = 0;
    uint64_t began = now();
    while (complete != 3) {
        for (unsigned lane = 0; lane < 2; lane++) {
            if (complete & (1U << lane))
                continue;
            struct inventory inventory = snapshot(lane);
            struct in6_addr eui = prefix_address(lane, 0, 1);
            memset(eui.s6_addr, 0, 8);
            eui.s6_addr[0] = 0xfe;
            eui.s6_addr[1] = 0x80;
            unsigned count = 0, ready = 0;
            for (unsigned at = 0; at < inventory.address_count; at++) {
                const struct address_record* value = inventory.addresses + at;
                if (!IN6_IS_ADDR_LINKLOCAL(&value->address))
                    continue;
                count++;
                if (value->flags & 0x48)
                    continue;
                int plain = !memcmp(&value->address, &eui, 16);
                check(value->flags == (plain ? 0x80 : 0x880) && value->preferred == UINT32_MAX &&
                          value->valid == UINT32_MAX,
                      "exact permanent link-local generation metadata");
                if (!stage) {
                    check(!plain, "initial stable generation uses a private link-local identifier");
                    stable[lane] = value->address;
                } else if (!plain)
                    check(!memcmp(&value->address, stable + lane, 16),
                          "generation mode changes preserve the existing stable link-local owner");
                ready++;
            }
            if (count != (stage ? 2U : 1U) || ready != count)
                continue;
            for (unsigned at = 0; at < inventory.address_count; at++) {
                const struct address_record* value = inventory.addresses + at;
                if (!IN6_IS_ADDR_LINKLOCAL(&value->address))
                    continue;
                char address[INET6_ADDRSTRLEN];
                check(inet_ntop(AF_INET6, &value->address, address, sizeof(address)) != NULL,
                      "link-local generation address formatting");
                printf("IPV6_DAD_LINK lane=%u stage=%u address=%s flags=%x preferred=%u valid=%u\n",
                       lane, stage, address, value->flags, value->preferred, value->valid);
            }
            complete |= 1U << lane;
        }
        check(now() - began < 5000000000ULL,
              "both generation modes complete actual link-local DAD");
        if (complete != 3)
            pause_poll();
    }
}

static void manual(unsigned lane, int remove) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "permanent DAD control socket");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr field;
        struct in6_addr value;
    } request = {0};

    request.header = (struct nlmsghdr){
        sizeof(request), remove ? RTM_DELADDR : RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_EXCL), 1, 0};
    request.address = (struct ifaddrmsg){AF_INET6, 64, 0, 0, indices[lane]};
    request.field = (struct rtattr){20, IFA_ADDRESS};
    request.value = prefix_address(lane, 5, 0);
    request.value.s6_addr[14] = 0xab;
    request.value.s6_addr[15] = 0xcd;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &request, sizeof(request), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(request),
          "permanent DAD address mutation");
    unsigned char response[256];
    readable(fd, POLLIN);
    ssize_t size = recv(fd, response, sizeof(response), 0);
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "permanent DAD address acknowledgement");
    struct nlmsgerr result;
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)response), sizeof(result));
    check(!result.error, "permanent DAD address result");
    close(fd);
}

static unsigned selected(const struct inventory* inventory, unsigned lane, unsigned scenario,
                         struct address_record* value) {
    struct in6_addr prefix = prefix_address(lane, scenario, 0);
    unsigned count = 0;
    for (unsigned at = 0; at < inventory->address_count; at++) {
        if (!memcmp(inventory->addresses[at].address.s6_addr, prefix.s6_addr, 8)) {
            *value = inventory->addresses[at];
            count++;
        }
    }
    check(count <= 2, "at most the retiring and replacement addresses own a tested prefix");
    return count;
}

static int candidate(const struct inventory* inventory, unsigned lane, unsigned scenario,
                     const struct in6_addr* previous, struct address_record* value) {
    struct in6_addr prefix = prefix_address(lane, scenario, 0);
    unsigned owners = 0, fresh = 0;
    for (unsigned at = 0; at < inventory->address_count; at++) {
        const struct address_record* entry = inventory->addresses + at;
        if (memcmp(entry->address.s6_addr, prefix.s6_addr, 8))
            continue;
        owners++;
        // Replacement insertion can precede removal or failure marking of the old owner.
        if (!memcmp(&entry->address, previous, 16) || entry->flags & IFA_F_DADFAILED)
            continue;
        *value = *entry;
        fresh++;
    }
    check(owners <= 2, "at most the retiring and replacement addresses own a tested prefix");
    check(fresh <= 1, "one fresh DAD candidate owns a tested prefix");
    return fresh;
}

static void observe(unsigned scenario, unsigned trial, unsigned kind, struct in6_addr previous[2]) {
    unsigned complete = 0;
    uint64_t began = now();
    while (complete != 3) {
        for (unsigned lane = 0; lane < 2; lane++) {
            if (complete & (1U << lane))
                continue;
            struct inventory inventory = snapshot(lane);
            struct address_record value;
            if (!candidate(&inventory, lane, scenario, previous + lane, &value))
                continue;
            unsigned flags = scenario == 4 ? 0x140 : scenario == 5 ? 0xc0 : 0x940;
            uint32_t preferred = scenario == 5 ? UINT32_MAX : 30;
            uint32_t valid = scenario == 5 ? UINT32_MAX : 60;
            check(value.flags == flags && value.preferred == preferred && value.valid == valid,
                  "first tentative observation retains exact flags and configured lifetimes");
            char address[INET6_ADDRSTRLEN];
            check(inet_ntop(AF_INET6, &value.address, address, sizeof(address)) != NULL,
                  "tentative DAD address formatting");
            printf("IPV6_DAD_ADDRESS lane=%u scenario=%u trial=%u address=%s flags=%x preferred=%u "
                   "valid=%u\n",
                   lane, scenario, trial, address, value.flags, value.preferred, value.valid);
            previous[lane] = value.address;
            control(lane, kind, scenario, trial, &value);
            complete |= 1U << lane;
        }
        check(now() - began < 8000000000ULL, "bounded next DAD candidate observation");
        if (complete != 3)
            pause_poll();
    }
}

static void final_state(unsigned scenario, unsigned expected_flags, int present) {
    uint64_t began = now();
    for (;;) {
        unsigned complete = 0;
        for (unsigned lane = 0; lane < 2; lane++) {
            struct inventory inventory = snapshot(lane);
            struct address_record value = {0};
            unsigned count = selected(&inventory, lane, scenario, &value);
            if (count == (unsigned)present && (!count || value.flags == expected_flags))
                complete++;
        }
        if (complete == 2)
            break;
        check(now() - began < 8000000000ULL, "actual DAD completion or exhausted removal");
        pause_poll();
    }
}

static void echo(unsigned lane, unsigned scenario, struct in6_addr source) {
    int fd = create(SOCK_DGRAM);
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "recovered stable address uses its actual adapter");
    struct sockaddr_in6 local = {
        .sin6_family = AF_INET6, .sin6_addr = source, .sin6_port = htons(48000 + lane)};
    struct sockaddr_in6 remote = {.sin6_family = AF_INET6, .sin6_port = htons(48010 + scenario)};
    remote.sin6_addr = prefix_address(lane, scenario, 0);
    remote.sin6_addr.s6_addr[15] = 0x42;
    bind_address(fd, local);
    connect_address(fd, remote);
    unsigned char payload[16] = {'D', 'A', 'D', 'C', lane, scenario};
    for (unsigned at = 6; at < sizeof(payload); at++)
        payload[at] = scenario * 7 + at;
    check(send(fd, payload, sizeof(payload), 0) == sizeof(payload), "recovered stable UDP output");
    unsigned char reply[16];
    receive_exact(fd, reply, sizeof(reply));
    check(!memcmp(reply, payload, sizeof(payload)), "complete recovered stable UDP reply");
    close(fd);
    printf("IPV6_DAD_UDP lane=%u scenario=%u bytes=16\n", lane, scenario);
}

static void finish(unsigned scenario, int present, unsigned flags) {
    if (scenario >= 2 && scenario <= 5) {
        uint64_t began = now();
        while (now() - began < 3100000000ULL) {
            final_state(scenario, flags, present);
            pause_poll();
        }
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        struct inventory inventory = snapshot(lane);
        struct address_record value = {0};
        unsigned count = selected(&inventory, lane, scenario, &value);
        check(count == (unsigned)present && (!count || value.flags == flags),
              "final DAD inventory remains stable");
        unsigned route_count = routes(&inventory, prefix_address(lane, scenario, 0), 64);
        int expires = 0;
        struct in6_addr prefix = prefix_address(lane, scenario, 0);
        for (unsigned at = 0; at < inventory.route_count; at++) {
            if (inventory.routes[at].prefix == 64 &&
                !memcmp(&inventory.routes[at].destination, &prefix, 16)) {
                expires = inventory.routes[at].expires;
                char destination[INET6_ADDRSTRLEN], gateway[INET6_ADDRSTRLEN];
                check(inet_ntop(AF_INET6, &inventory.routes[at].destination, destination,
                                sizeof(destination)) != NULL &&
                          inet_ntop(AF_INET6, &inventory.routes[at].gateway, gateway,
                                    sizeof(gateway)) != NULL,
                      "actual learned prefix route formatting");
                printf("IPV6_DAD_ROUTE lane=%u scenario=%u destination=%s/64 gateway=%s metric=%u "
                       "protocol=%u expires=%d\n",
                       lane, scenario, destination, gateway, inventory.routes[at].metric,
                       inventory.routes[at].protocol, expires);
            }
        }
        printf("IPV6_DAD_FINISH lane=%u scenario=%u count=%u flags=%x preferred=%u valid=%u "
               "prefix_routes=%u expires=%d observed_ns=%llu\n",
               lane, scenario, count, value.flags, value.preferred, value.valid, route_count,
               expires, (unsigned long long)now());
        if (scenario != 5)
            check(route_count == (scenario == 2 ? 0U
                                  : scenario == 3 || scenario == 4
                                      ? (unsigned)retain_exhausted_routes
                                      : 1U),
                  "independent learned on-link prefix ownership");
        if (scenario == 6)
            check(expires > 0 && expires < 5800,
                  "regeneration leaves the original on-link route deadline");
        control(lane, 4, scenario, 0, NULL);
    }
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--retain-exhausted-routes")),
          "explicit audited native prefix-cleanup policy");
    retain_exhausted_routes = argc == 2;
    scalar("all", "disable_ipv6", 1);
    scalar("default", "disable_ipv6", 1);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "DAD adapter control");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(fd, SIOCGIFINDEX, &request), "DAD adapter index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(fd, SIOCGIFHWADDR, &request), "DAD adapter MAC");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        request.ifr_flags = IFF_UP;
        check(!ioctl(fd, SIOCSIFFLAGS, &request), "DAD adapter up");
        const char* properties[] = {"addr_gen_mode",        "accept_ra",     "autoconf",
                                    "router_solicitations", "dad_transmits", "enhanced_dad"};
        const int values[] = {2, 1, 1, 0, 1, 1};
        char path[160];
        snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/stable_secret", request.ifr_name);
        int secret = open(path, O_WRONLY | O_CLOEXEC);
        const char bytes[] = "2001:db8:6d00::1234\n";
        check(secret >= 0 && write(secret, bytes, sizeof(bytes) - 1) == sizeof(bytes) - 1,
              "explicit stable address secret");
        close(secret);
        for (unsigned at = 0; at < sizeof(values) / sizeof(*values); at++)
            scalar(request.ifr_name, properties[at], values[at]);
        packets[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                               htons(IPV6_BARRIER_PROTOCOL));
        check(packets[lane] >= 0, "DAD observation Ethernet socket");
        struct sockaddr_ll binding = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(IPV6_BARRIER_PROTOCOL),
                                      .sll_ifindex = indices[lane]};
        check(!bind(packets[lane], (struct sockaddr*)&binding, sizeof(binding)),
              "DAD observation binding");
    }
    controls(0, 0);
    scalar("eth0", "disable_ipv6", 0);
    scalar("eth1", "disable_ipv6", 0);
    links_ready(0);
    for (unsigned scenario = 1; scenario <= 6; scenario++) {
        if (scenario == 4 || scenario == 5)
            controls(6, scenario);
        scalar("eth0", "addr_gen_mode", scenario == 4 ? 0 : 2);
        scalar("eth1", "addr_gen_mode", scenario == 4 ? 0 : 2);
        if (scenario == 4 || scenario == 5)
            links_ready(scenario);
        scalar("eth0", "dad_transmits", scenario == 6 ? 3 : 1);
        scalar("eth1", "dad_transmits", scenario == 6 ? 3 : 1);
        controls(1, scenario);
        if (scenario == 5)
            for (unsigned lane = 0; lane < 2; lane++)
                manual(lane, 0);
        struct in6_addr previous[2] = {0};
        unsigned trials = scenario == 2 || scenario == 3   ? 4
                          : scenario == 1 || scenario == 6 ? 2
                                                           : 1;
        for (unsigned trial = 0; trial < trials; trial++)
            observe(scenario, trial, (scenario == 1 || scenario == 6) && trial == 1 ? 3 : 2,
                    previous);
        int usable = scenario == 1 || scenario == 6;
        unsigned flags = usable ? 0x900 : scenario == 5 ? 0xc8 : 0;
        final_state(scenario, flags, usable || scenario == 5);
        if (usable)
            for (unsigned lane = 0; lane < 2; lane++)
                echo(lane, scenario, previous[lane]);
        finish(scenario, usable || scenario == 5, flags);
        if (scenario == 5) {
            for (unsigned lane = 0; lane < 2; lane++)
                manual(lane, 1);
            final_state(scenario, 0, 0);
            controls(5, scenario);
        }
    }
    controls(9, 0);
    for (unsigned lane = 0; lane < 2; lane++)
        close(packets[lane]);
    close(fd);
    puts("IPV6_DAD_PASS adapters=2 scenarios_each=6 tentative_each=14 conflicts_each=12 "
         "global_probes_each=18 link_probes_each=2 exhausted_observation_seconds=3");
    return 0;
}
