// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_multicast_source_delivery.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static unsigned indices[2];
static int query_case, mtu_case, overlap_case, bounds_case;
static unsigned char macs[2][6];
static int controls[2], owners[2];
static const uint32_t group = 0xef7f2a01, first = 0xc0000201;

static void need(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "IPV4_SOURCE_WIRE_FAIL operation=%s errno=%d\n", label, errno);
        exit(1);
    }
}

static unsigned long long monotonic(void) {
    struct timespec now;
    need(!clock_gettime(CLOCK_MONOTONIC, &now), "monotonic clock");
    return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static struct sockaddr_in address(uint32_t value) {
    return (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(value)};
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    need(fd >= 0, "interface control socket");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, IFNAMSIZ, "eth%u", lane);
        need(!ioctl(fd, SIOCGIFINDEX, &request), "interface index");
        indices[lane] = request.ifr_ifindex;
        need(!ioctl(fd, SIOCGIFHWADDR, &request), "interface hardware address");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        struct sockaddr_in local = address(0x0a430102 + (lane << 8));
        memcpy(&request.ifr_addr, &local, sizeof(local));
        need(!ioctl(fd, SIOCSIFADDR, &request), "interface address");
        local = address(0xffffff00);
        memcpy(&request.ifr_netmask, &local, sizeof(local));
        need(!ioctl(fd, SIOCSIFNETMASK, &request), "interface netmask");
        if (mtu_case) {
            request.ifr_mtu = 68;
            need(!ioctl(fd, SIOCSIFMTU, &request), "minimum interface MTU");
            need(!ioctl(fd, SIOCGIFMTU, &request) && request.ifr_mtu == 68,
                 "actual minimum interface MTU");
        }
        if (bounds_case) {
            need(!ioctl(fd, SIOCGIFMTU, &request) && request.ifr_mtu == 1500,
                 "source query actual Ethernet MTU");
            printf("{\"kind\":\"query-link\",\"lane\":%u,\"mtu\":%d}\n", lane, request.ifr_mtu);
        }
        request.ifr_flags = IFF_UP;
        need(!ioctl(fd, SIOCSIFFLAGS, &request), "interface activation");
        controls[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(0x88b9));
        struct sockaddr_ll link = {.sll_family = AF_PACKET,
                                   .sll_protocol = htons(0x88b9),
                                   .sll_ifindex = (int)indices[lane]};
        need(controls[lane] >= 0 && !bind(controls[lane], (struct sockaddr*)&link, sizeof(link)),
             "control socket binding");
        owners[lane] = socket(AF_INET, SOCK_DGRAM, 0);
        need(owners[lane] >= 0, "membership socket");
    }
    need(!close(fd), "close interface control socket");
}

static void exchange(unsigned stage, int done) {
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned char frame[60] = {0};
        unsigned char peer[6] = {2, 0x41, 0x58, 0x4d, 0x43, (unsigned char)lane};
        memcpy(frame, peer, 6);
        memcpy(frame + 6, macs[lane], 6);
        frame[12] = 0x88;
        frame[13] = 0xb9;
        memcpy(frame + 14, done ? "AXSD" : "AXSB", 4);
        frame[18] = lane;
        frame[19] = stage;
        struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                     .sll_protocol = htons(0x88b9),
                                     .sll_ifindex = (int)indices[lane],
                                     .sll_halen = 6};
        memcpy(target.sll_addr, peer, 6);
        need(sendto(controls[lane], frame, sizeof(frame), 0, (struct sockaddr*)&target,
                    sizeof(target)) == sizeof(frame),
             "stage control request");
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        struct pollfd ready = {.fd = controls[lane], .events = POLLIN};
        need(poll(&ready, 1, 4000) == 1 && (ready.revents & POLLIN),
             "stage acknowledgment deadline");
        unsigned char reply[128], peer[6] = {2, 0x41, 0x58, 0x4d, 0x43, (unsigned char)lane};
        need(recv(controls[lane], reply, sizeof(reply), 0) == 60 && !memcmp(reply, macs[lane], 6) &&
                 !memcmp(reply + 6, peer, 6) && reply[12] == 0x88 && reply[13] == 0xb9 &&
                 !memcmp(reply + 14, "AXSA", 4) && reply[18] == lane && reply[19] == stage &&
                 reply[20] == (done ? 'D' : 'B'),
             "physical stage and peer identity");
    }
}

static int get_policy(void) {
    int fd = open("/proc/sys/net/ipv4/igmp_max_msf", O_RDONLY | O_CLOEXEC);
    need(fd >= 0, "open source policy");
    char bytes[32];
    ssize_t count = read(fd, bytes, sizeof(bytes) - 1);
    need(count > 0 && !close(fd), "read source policy");
    bytes[count] = 0;
    char* end;
    errno = 0;
    long value = strtol(bytes, &end, 10);
    need(!errno && value >= 0 && value <= INT32_MAX && end != bytes &&
             (!*end || !strcmp(end, "\n")),
         "actual source policy integer");
    return (int)value;
}

static void set_policy(int value) {
    int fd = open("/proc/sys/net/ipv4/igmp_max_msf", O_WRONLY | O_CLOEXEC);
    need(fd >= 0, "open writable source policy");
    char bytes[32];
    int count = snprintf(bytes, sizeof(bytes), "%d\n", value);
    need(count > 0 && write(fd, bytes, count) == count && !close(fd), "set source policy");
    need(get_policy() == value, "source policy readback");
}

static void change(unsigned lane, unsigned stage, int option, const void* value, socklen_t length) {
    unsigned long long begin = monotonic();
    errno = 0;
    int result = setsockopt(owners[lane], IPPROTO_IP, option, value, length);
    int error = result < 0 ? errno : 0;
    unsigned long long end = monotonic();
    printf("{\"kind\":\"action\",\"lane\":%u,\"stage\":%u,\"option\":%d,\"returncode\":%d,"
           "\"errno\":%d,\"begin_ns\":%llu,\"end_ns\":%llu}\n",
           lane, stage, option, result, error, begin, end);
    need(result == 0 && error == 0, "source membership transition");
}

static void change_mtu(unsigned lane, unsigned stage) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    need(fd >= 0, "live MTU control socket");
    struct ifreq request = {0};
    snprintf(request.ifr_name, IFNAMSIZ, "eth%u", lane);
    request.ifr_mtu = 1500;
    unsigned long long begin = monotonic();
    int result = ioctl(fd, SIOCSIFMTU, &request);
    need(result == 0 && !ioctl(fd, SIOCGIFMTU, &request) && request.ifr_mtu == 1500,
         "live MTU update and readback");
    printf("{\"kind\":\"mtu-change\",\"lane\":%u,\"stage\":%u,\"returncode\":%d,\"mtu\":%d,\"begin_"
           "ns\":%llu,\"end_ns\":%llu}\n",
           lane, stage, result, request.ifr_mtu, begin, monotonic());
    need(!close(fd), "close live MTU control socket");
}

static void mtu_action(unsigned lane, unsigned stage) {
    if (stage == 1 || stage == 7) {
        struct ip_mreqn membership = {.imr_multiaddr.s_addr = htonl(group),
                                      .imr_ifindex = (int)indices[lane]};
        change(lane, stage, stage == 1 ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &membership,
               sizeof(membership));
        return;
    }

    union {
        uint64_t alignment;
        unsigned char bytes[IP_MSFILTER_SIZE(64)];
    } storage = {0};
    struct ip_msfilter* filter = (struct ip_msfilter*)storage.bytes;
    filter->imsf_multiaddr.s_addr = htonl(group);
    filter->imsf_interface.s_addr = htonl(0x0a430102 + (lane << 8));
    filter->imsf_fmode = stage == 2 ? MCAST_INCLUDE : MCAST_EXCLUDE;
    filter->imsf_numsrc = 64;
    for (unsigned n = 0; n < 64; n++)
        filter->imsf_slist[n].s_addr = htonl(first + n);
    change(lane, stage, IP_MSFILTER, filter, sizeof(storage.bytes));
}

static void overlap_action(unsigned lane, unsigned stage) {
    if (stage == 1 || stage == 7) {
        mtu_action(lane, stage);
        return;
    }
    struct ip_mreq_source source = {.imr_multiaddr.s_addr = htonl(group),
                                    .imr_interface.s_addr = htonl(0x0a430102 + (lane << 8)),
                                    .imr_sourceaddr.s_addr = htonl(first + (stage >= 4))};
    if (stage == 3) {
        change(lane, stage, IP_UNBLOCK_SOURCE, &source, sizeof(source));
        change(lane, stage, IP_BLOCK_SOURCE, &source, sizeof(source));
    } else if (stage == 4) {
        change(lane, stage, IP_BLOCK_SOURCE, &source, sizeof(source));
        change(lane, stage, IP_UNBLOCK_SOURCE, &source, sizeof(source));
    } else
        change(lane, stage, stage == 6 ? IP_UNBLOCK_SOURCE : IP_BLOCK_SOURCE, &source,
               sizeof(source));
}

static void action(unsigned lane, unsigned stage, unsigned transition) {
    struct ip_mreq_source source = {.imr_multiaddr.s_addr = htonl(group),
                                    .imr_interface.s_addr = htonl(0x0a430102 + (lane << 8))};
    int option;
    switch (transition) {
    case 1:
        option = IP_ADD_SOURCE_MEMBERSHIP;
        source.imr_sourceaddr.s_addr = htonl(first);
        break;
    case 2:
        option = IP_ADD_SOURCE_MEMBERSHIP;
        source.imr_sourceaddr.s_addr = htonl(first + 1);
        break;
    case 3:
        option = IP_DROP_SOURCE_MEMBERSHIP;
        source.imr_sourceaddr.s_addr = htonl(first);
        break;
    case 4:
        option = IP_MSFILTER;
        break;
    case 5:
        option = IP_BLOCK_SOURCE;
        source.imr_sourceaddr.s_addr = htonl(first + 3);
        break;
    case 6:
        option = IP_UNBLOCK_SOURCE;
        source.imr_sourceaddr.s_addr = htonl(first + 2);
        break;
    default:
        option = IP_DROP_MEMBERSHIP;
        break;
    }
    if (transition == 4) {
        struct ip_msfilter filter = {
            .imsf_multiaddr.s_addr = htonl(group),
            .imsf_interface = source.imr_interface,
            .imsf_fmode = MCAST_EXCLUDE,
            .imsf_numsrc = 1,
            .imsf_slist = {{.s_addr = htonl(first + ((query_case || bounds_case) ? 0 : 2))}}};
        change(lane, stage, option, &filter, IP_MSFILTER_SIZE(1));
    } else if (transition == 7) {
        struct ip_mreqn membership = {.imr_multiaddr.s_addr = htonl(group),
                                      .imr_ifindex = (int)indices[lane]};
        change(lane, stage, option, &membership, sizeof(membership));
    } else
        change(lane, stage, option, &source, sizeof(source));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char* scenario = getenv("AXIOM64_SOURCE_CASE");
    if (!scenario)
        scenario = "settled";
    query_case = !strcmp(scenario, "queries");
    bounds_case = !strcmp(scenario, "query-bounds");
    mtu_case = !strcmp(scenario, "mtu");
    overlap_case = !strcmp(scenario, "overlap");
    int delivery_case = !strcmp(scenario, "delivery");
    need(query_case || mtu_case || overlap_case || delivery_case || bounds_case ||
             !strcmp(scenario, "settled"),
         "known source packet case");
    struct utsname identity;
    need(!uname(&identity), "kernel identity");
    printf("{\"kind\":\"kernel\",\"sysname\":\"%s\",\"release\":\"%s\",\"case\":\"%s\"}\n",
           identity.sysname, identity.release, scenario);
    configure();
    if (delivery_case) {
        ipv4_source_delivery(indices, exchange);
        for (unsigned lane = 0; lane < 2; lane++)
            need(!close(owners[lane]) && !close(controls[lane]), "delivery control final close");
        puts("IPV4_SOURCE_WIRE_DELIVERY_PASS stages=8 lanes=2 actions=48 sends=32 receives=92 "
             "quiet_windows=16 source_phases=8");
        return 0;
    }
    int original_policy = -1;
    if (mtu_case) {
        original_policy = get_policy();
        need(original_policy == 10, "original source policy");
        set_policy(64);
        printf("{\"kind\":\"policy\",\"phase\":\"configured\",\"previous\":%d,\"value\":%d,\"mtu\":"
               "68}\n",
               original_policy, get_policy());
    }
    unsigned stages = bounds_case ? 8 : mtu_case ? 7 : query_case ? 12 : 7;
    for (unsigned stage = 1; stage <= stages; stage++) {
        unsigned transition = stage;
        if (query_case)
            transition = stage == 1 ? 1 : stage == 2 ? 2 : stage == 7 ? 4 : stage == 12 ? 7 : 0;
        if (mtu_case)
            transition = stage == 3 || stage == 5 || stage == 6 ? 0 : stage;
        if (bounds_case)
            transition = stage == 1 ? 1 : stage == 5 ? 4 : stage == 8 ? 7 : 0;
        exchange(stage, 0);
        for (unsigned lane = 0; lane < 2; lane++) {
            if (overlap_case)
                overlap_action(lane, stage);
            else if (mtu_case && stage == 6)
                change_mtu(lane, stage);
            else if (mtu_case && transition)
                mtu_action(lane, stage);
            else if (transition)
                action(lane, stage, transition);
            else
                printf(
                    "{\"kind\":\"query-ready\",\"lane\":%u,\"stage\":%u,\"monotonic_ns\":%llu}\n",
                    lane, stage, monotonic());
        }
        unsigned long long begin = monotonic();
        exchange(stage, 1);
        printf("{\"kind\":\"observation\",\"stage\":%u,\"begin_ns\":%llu,\"end_ns\":%llu}\n", stage,
               begin, monotonic());
    }
    for (unsigned lane = 0; lane < 2; lane++)
        need(!close(owners[lane]) && !close(controls[lane]), "final socket close");
    if (mtu_case) {
        set_policy(original_policy);
        printf("{\"kind\":\"policy\",\"phase\":\"restored\",\"value\":%d}\n", get_policy());
    }
    puts(
        bounds_case ? "IPV4_SOURCE_WIRE_QUERY_BOUNDS_PASS stages=8 lanes=2 operations=6 queries=10 "
                      "large_query_sources=65 maximum_query_sources=366"
        : overlap_case ? "IPV4_SOURCE_WIRE_OVERLAP_PASS stages=7 lanes=2 operations=18 "
                         "first_packet_barriers=4 full_observations_each=5"
        : mtu_case ? "IPV4_SOURCE_WIRE_MTU_PASS stages=7 lanes=2 operations=8 queries=6 sources=64 "
                     "minimum_mtu=68 "
                     "restored_mtu=1500 restored_policy=10"
        : query_case ? "IPV4_SOURCE_WIRE_QUERY_PASS stages=12 lanes=2 operations=8 queries=16"
                     : "IPV4_SOURCE_WIRE_PASS stages=7 lanes=2 operations=14");
    return 0;
}
