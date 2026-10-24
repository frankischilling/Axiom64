// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_OWNER"
#define IPV6_BARRIER_PROTOCOL 0x88c3
#define IPV6_BARRIER_MAGIC "IP6O"
#include "ipv6_fixture.h"
#include <fcntl.h>
#include "ipv6_dad_inventory.h"

// ADDRESS and CONFLICT carry queried address metadata. SUMMARY carries the
// queried address count and connected-prefix count in its first two fields.
enum operation {
    HELLO,
    BEGIN,
    ADDRESS,
    SUMMARY,
    CONFLICT,
    MODE,
    DELETE,
    END,
    FINISH,
    FIRST,
    READY
};

static unsigned phases[2];
static int retain_routes;

static void pause_poll(void) {
    struct timespec delay = {0, 20000000};
    check(!nanosleep(&delay, NULL), "owner inventory polling");
}

static void control(unsigned lane, unsigned kind, unsigned scenario, unsigned stage,
                    const struct address_record* value) {
    unsigned phase = phases[lane]++;
    check(phase < 255, "bounded ownership controls");
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = IPV6_BARRIER_PROTOCOL >> 8;
    frame[13] = IPV6_BARRIER_PROTOCOL & 255;
    memcpy(frame + 14, IPV6_BARRIER_MAGIC, 4);
    frame[18] = lane;
    frame[19] = phase;
    frame[20] = kind;
    frame[21] = scenario;
    frame[22] = stage;
    frame[23] = kind == HELLO && retain_routes;
    if (value) {
        uint32_t fields[] = {htonl(value->flags), htonl(value->preferred), htonl(value->valid)};
        memcpy(frame + 24, fields, sizeof(fields));
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
          "complete ownership control");
    uint64_t began = now();
    for (;;) {
        unsigned char reply[1600];
        struct pollfd item = {.fd = packets[lane], .events = POLLIN};
        check(poll(&item, 1, 100) >= 0, "ownership control readiness");
        ssize_t size = recv(packets[lane], reply, sizeof(reply), MSG_DONTWAIT);
        if (size == 60 && !memcmp(reply, macs[lane], 6) && !memcmp(reply + 6, frame, 6) &&
            !memcmp(reply + 12, frame + 12, 8) && reply[20] == 1 &&
            !memcmp(reply + 21, (unsigned char[39]){0}, 39))
            break;
        check(now() - began < 10000000000ULL, "finite ownership control");
    }
    printf("IPV6_OWNER_CONTROL lane=%u phase=%u kind=%u case=%u stage=%u flags=%x "
           "preferred=%u valid=%u target=",
           lane, phase, kind, scenario, stage, value ? value->flags : 0,
           value ? value->preferred : 0, value ? value->valid : 0);
    for (unsigned at = 36; at < 52; at++)
        printf("%02x", frame[at]);
    printf(" observed_ns=%llu\n", (unsigned long long)stamp);
}

static void controls(unsigned kind, unsigned scenario, unsigned stage) {
    for (unsigned lane = 0; lane < 2; lane++)
        control(lane, kind, scenario, stage, NULL);
}

static void property(unsigned lane, const char* name, int value) {
    char scope[16];
    snprintf(scope, sizeof(scope), "eth%u", lane);
    scalar(scope, name, value);
}

static int mutate(unsigned lane, struct in6_addr value, int remove, unsigned flags,
                  unsigned address_flags, uint32_t preferred, uint32_t valid) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "ownership netlink control");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr address_field;
        struct in6_addr value;
        struct rtattr cache_field;
        struct ifa_cacheinfo cache;
    } request = {0};

    request.header = (struct nlmsghdr){sizeof(request), remove ? RTM_DELADDR : RTM_NEWADDR,
                                       NLM_F_REQUEST | NLM_F_ACK | flags, 1, 0};
    request.address = (struct ifaddrmsg){AF_INET6, 64, address_flags, 0, indices[lane]};
    request.address_field = (struct rtattr){20, IFA_ADDRESS};
    request.value = value;
    request.cache_field = (struct rtattr){20, IFA_CACHEINFO};
    request.cache.ifa_prefered = preferred;
    request.cache.ifa_valid = valid;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &request, sizeof(request), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(request),
          "actual ownership address mutation");
    unsigned char response[256];
    readable(fd, POLLIN);
    ssize_t size = recv(fd, response, sizeof(response), 0);
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "ownership netlink acknowledgement");
    struct nlmsgerr result;
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)response), sizeof(result));
    close(fd);
    return result.error;
}

static int matches(const struct address_record* value, unsigned lane, unsigned scenario, int link) {
    if (link)
        return IN6_IS_ADDR_LINKLOCAL(&value->address);
    struct in6_addr prefix = prefix_address(lane, scenario, 0);
    return !memcmp(value->address.s6_addr, prefix.s6_addr, 8);
}

static void report(unsigned lane, unsigned scenario, unsigned stage, int link) {
    struct inventory inventory = snapshot(lane);
    unsigned count = 0;
    for (unsigned at = 0; at < inventory.address_count; at++) {
        const struct address_record* value = inventory.addresses + at;
        if (matches(value, lane, scenario, link)) {
            control(lane, ADDRESS, scenario, stage, value);
            count++;
        }
    }
    struct in6_addr prefix = prefix_address(lane, scenario, 0);
    if (link) {
        memset(&prefix, 0, sizeof(prefix));
        prefix.s6_addr[0] = 0xfe;
        prefix.s6_addr[1] = 0x80;
    }
    struct address_record summary = {
        .flags = count, .preferred = routes(&inventory, prefix, 64), .address = prefix};
    control(lane, SUMMARY, scenario, stage, &summary);
}

static void reports(unsigned scenario, unsigned stage, int link) {
    for (unsigned lane = 0; lane < 2; lane++)
        report(lane, scenario, stage, link);
}

static struct address_record exact(unsigned lane, struct in6_addr address) {
    struct inventory inventory = snapshot(lane);
    struct address_record result = {0};
    unsigned count = 0;
    for (unsigned at = 0; at < inventory.address_count; at++)
        if (!memcmp(&inventory.addresses[at].address, &address, 16)) {
            result = inventory.addresses[at];
            count++;
        }
    check(count == 1, "one actual queried owner");
    return result;
}

static void wait_pair(unsigned scenario, int link, int tentative, struct address_record values[2]) {
    unsigned complete = 0;
    uint64_t began = now();
    while (complete != 3) {
        for (unsigned lane = 0; lane < 2; lane++) {
            if (complete & (1U << lane))
                continue;
            struct inventory inventory = snapshot(lane);
            unsigned found = 0;
            for (unsigned at = 0; at < inventory.address_count; at++) {
                const struct address_record* value = inventory.addresses + at;
                if (!matches(value, lane, scenario, link) || (value->flags & IFA_F_DADFAILED) ||
                    !!(value->flags & IFA_F_TENTATIVE) != tentative)
                    continue;
                values[lane] = *value;
                found++;
            }
            check(found <= 1, "one selected active ownership candidate");
            if (found)
                complete |= 1U << lane;
        }
        check(now() - began < 8000000000ULL, "bounded actual ownership observation");
        if (complete != 3)
            pause_poll();
    }
}

static void reset(unsigned scenario, int mode) {
    for (unsigned lane = 0; lane < 2; lane++)
        property(lane, "disable_ipv6", 1);
    for (unsigned lane = 0; lane < 2; lane++) {
        struct inventory inventory = snapshot(lane);
        check(!inventory.address_count && !inventory.route_count,
              "IPv6 disable withdraws prior address and route owners");
        property(lane, "addr_gen_mode", mode);
    }
    controls(BEGIN, scenario, mode);
    for (unsigned lane = 0; lane < 2; lane++)
        property(lane, "disable_ipv6", 0);
}

static void remove_owner(unsigned lane, unsigned scenario, unsigned stage, struct in6_addr value) {
    int result = mutate(lane, value, 1, 0, 0, 0, 0);
    struct address_record observed = {.address = value, .flags = (uint32_t)result};
    control(lane, DELETE, scenario, stage, &observed);
}

static void recovery(unsigned scenario, int link, const struct address_record old[2]) {
    uint64_t began = now();
    unsigned first = 0, ready = 0;
    while (now() - began < 4100000000ULL) {
        for (unsigned lane = 0; lane < 2; lane++) {
            struct inventory inventory = snapshot(lane);
            for (unsigned at = 0; at < inventory.address_count; at++) {
                const struct address_record* value = inventory.addresses + at;
                if (!matches(value, lane, scenario, link) || (value->flags & IFA_F_DADFAILED) ||
                    !memcmp(&value->address, &old[lane].address, 16))
                    continue;
                // Mode changes also add an EUI-64 owner; observe the stable retry separately.
                struct in6_addr eui = prefix_address(lane, scenario, 1);
                if (link) {
                    memset(eui.s6_addr, 0, 8);
                    eui.s6_addr[0] = 0xfe;
                    eui.s6_addr[1] = 0x80;
                }
                if (!memcmp(&value->address, &eui, 16))
                    continue;
                if (!(first & (1U << lane))) {
                    control(lane, FIRST, scenario, 0, value);
                    first |= 1U << lane;
                }
                if (!(value->flags & IFA_F_TENTATIVE) && !(ready & (1U << lane))) {
                    control(lane, READY, scenario, 0, value);
                    ready |= 1U << lane;
                }
            }
        }
        pause_poll();
    }
    check(first == 3 && ready == 3, "both actual stable retries become ready");
}

static void global_cases(void) {
    for (unsigned scenario = 1; scenario <= 4; scenario++) {
        reset(scenario, scenario == 2 ? 0 : 2);
        struct address_record links[2], original[2];
        wait_pair(scenario, 1, 0, links);
        reports(scenario, 0, 1);
        wait_pair(scenario, 0, scenario != 2, original);
        reports(scenario, 1, 0);
        for (unsigned lane = 0; lane < 2; lane++) {
            check(!mutate(lane, original[lane].address, 0, NLM_F_CREATE | NLM_F_REPLACE,
                          scenario == 2 || scenario == 3 ? IFA_F_NODAD : 0,
                          scenario == 4 ? 6 : UINT32_MAX, scenario == 4 ? 10 : UINT32_MAX),
                  "manual takeover of actual generated owner");
        }
        reports(scenario, 2, 0);
        if (scenario == 2) {
            for (unsigned lane = 0; lane < 2; lane++)
                remove_owner(lane, scenario, 0, original[lane].address);
            reports(scenario, 5, 0);
        } else {
            for (unsigned lane = 0; lane < 2; lane++) {
                struct address_record value = exact(lane, original[lane].address);
                control(lane, CONFLICT, scenario, 0, &value);
            }
            recovery(scenario, 0, original);
            reports(scenario, 3, 0);
            struct address_record replacement[2];
            wait_pair(scenario, 0, 0, replacement);
            for (unsigned lane = 0; lane < 2; lane++)
                remove_owner(lane, scenario, 0, original[lane].address);
            reports(scenario, 4, 0);
            for (unsigned lane = 0; lane < 2; lane++)
                remove_owner(lane, scenario, 1, replacement[lane].address);
            reports(scenario, 5, 0);
        }
        controls(END, scenario, 0);
    }
}

static void lifecycle_cases(void) {
    for (unsigned scenario = 5; scenario <= 9; scenario++) {
        int link = scenario <= 7;
        reset(scenario, link ? 2 : 1);
        struct address_record originals[2] = {0};
        if (!link) {
            for (unsigned lane = 0; lane < 2; lane++) {
                struct in6_addr value = prefix_address(lane, scenario, 0);
                value.s6_addr[15] = 0x23;
                check(!mutate(lane, value, 0, NLM_F_CREATE | NLM_F_EXCL, 0, 2, 8),
                      "finite configured owner creation");
            }
        }
        unsigned trials = scenario == 7 ? 4 : 1;
        for (unsigned trial = 0; trial < trials; trial++) {
            struct address_record values[2];
            wait_pair(scenario, link, 1, values);
            if (!trial)
                memcpy(originals, values, sizeof(originals));
            if (scenario == 6) {
                // Mark the change before its first possible EUI-64 probe.
                controls(MODE, scenario, 0);
                for (unsigned lane = 0; lane < 2; lane++) {
                    property(lane, "addr_gen_mode", 0);
                    char path[128], bytes[16] = {0};
                    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/eth%u/addr_gen_mode",
                             lane);
                    int configuration = open(path, O_RDONLY | O_CLOEXEC);
                    check(configuration >= 0 &&
                              read(configuration, bytes, sizeof(bytes) - 1) == 2 &&
                              !strcmp(bytes, "0\n"),
                          "actual mode-zero readback before conflict");
                    close(configuration);
                }
            }
            for (unsigned lane = 0; lane < 2; lane++) {
                values[lane] = exact(lane, values[lane].address);
                control(lane, CONFLICT, scenario, trial, &values[lane]);
            }
        }
        if (scenario == 5 || scenario == 6)
            recovery(scenario, 1, originals);
        else {
            uint64_t began = now();
            while (now() - began < 4100000000ULL)
                pause_poll();
        }
        reports(scenario, 3, link);
        if (!link) {
            for (unsigned lane = 0; lane < 2; lane++) {
                check(!mutate(lane, originals[lane].address, 0, NLM_F_REPLACE,
                              scenario == 9 ? IFA_F_NODAD : 0, 2, 8),
                      "recreate the removed finite configured owner");
            }
            reports(scenario, 4, 0);
            // Observe one full DAD interval after the recreation metadata. Native
            // NODAD must emit no extra probe; ordinary recreation must emit one.
            uint64_t began = now();
            while (now() - began < 1100000000ULL)
                pause_poll();
            if (scenario == 8) {
                // Native DAD also has an initial randomized delay. Wait for
                // actual completion, retaining the same two/eight-second input.
                struct address_record ready[2];
                wait_pair(scenario, 0, 0, ready);
            }
            reports(scenario, 5, 0);
        }
        controls(END, scenario, 0);
    }
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    check((argc == 3 || argc == 4) && !strcmp(argv[1], "--group") &&
              (!strcmp(argv[2], "global") || !strcmp(argv[2], "lifecycle")) &&
              (argc == 3 || !strcmp(argv[3], "--retain-exhausted-routes")),
          "known ownership group and pinned prefix policy");
    int global = !strcmp(argv[2], "global");
    retain_routes = argc == 4;
    scalar("all", "disable_ipv6", 1);
    scalar("default", "disable_ipv6", 1);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "ownership adapter control");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(fd, SIOCGIFINDEX, &request), "ownership adapter index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(fd, SIOCGIFHWADDR, &request), "ownership adapter MAC");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        request.ifr_flags = IFF_UP;
        check(!ioctl(fd, SIOCSIFFLAGS, &request), "ownership adapter up");
        const char* properties[] = {"accept_ra", "autoconf", "router_solicitations",
                                    "dad_transmits", "enhanced_dad"};
        const int values[] = {1, 1, 0, 1, 1};
        char path[160];
        snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/stable_secret", request.ifr_name);
        int secret = open(path, O_WRONLY | O_CLOEXEC);
        const char bytes[] = "2001:db8:6d00::1234\n";
        check(secret >= 0 && write(secret, bytes, sizeof(bytes) - 1) == sizeof(bytes) - 1,
              "explicit ownership stable secret");
        close(secret);
        for (unsigned at = 0; at < sizeof(values) / sizeof(*values); at++)
            scalar(request.ifr_name, properties[at], values[at]);
        packets[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                               htons(IPV6_BARRIER_PROTOCOL));
        check(packets[lane] >= 0, "ownership observation socket");
        struct sockaddr_ll binding = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(IPV6_BARRIER_PROTOCOL),
                                      .sll_ifindex = indices[lane]};
        check(!bind(packets[lane], (struct sockaddr*)&binding, sizeof(binding)),
              "ownership observation binding");
    }
    controls(HELLO, 0, global ? 0 : 1);
    if (global)
        global_cases();
    else
        lifecycle_cases();
    controls(FINISH, 0, 0);
    for (unsigned lane = 0; lane < 2; lane++)
        close(packets[lane]);
    close(fd);
    printf("IPV6_OWNER_PASS adapters=2 group=%s cases_each=%u quiet_seconds=4\n",
           global ? "global" : "lifecycle", global ? 4 : 5);
    return 0;
}