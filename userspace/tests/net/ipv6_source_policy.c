// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct candidate {
    const char* address;
    unsigned prefix, deprecated, other;
};

struct source_case {
    const char *name, *destination;
    struct candidate candidates[3];
    const char* selected;
    int error;
};

// Recorded Linux UDP connect/getsockname outcomes with its default label table.
static const struct source_case cases[] = {
    {"outgoing-before-prefix",
     "2001:db8:99::2",
     {{"2001:db8:10::1", 64, 0, 0}, {"2001:db8:99::1", 128, 0, 1}},
     "2001:db8:10::1",
     0},
    {"other-interface-fallback",
     "2001:db8:99::2",
     {{"fe80::10", 64, 0, 0}, {"2001:db8:99::1", 64, 0, 1}},
     "2001:db8:99::1",
     0},
    {"deprecated-before-interface",
     "2001:db8:99::2",
     {{"2001:db8:10::1", 64, 1, 0}, {"2001:db8:99::1", 64, 0, 1}},
     "2001:db8:99::1",
     0},
    {"outgoing-before-label",
     "fd42::2",
     {{"2001:db8:10::1", 64, 0, 0}, {"fd42::1", 64, 0, 1}},
     "2001:db8:10::1",
     0},
    {"label-ula", "fd42::2", {{"fd42::1", 0, 0, 0}, {"2001:db8:10::1", 128, 0, 0}}, "fd42::1", 0},
    {"label-global",
     "2001:db8:99::2",
     {{"2001:db8:10::1", 0, 0, 0}, {"fd42::1", 128, 0, 0}},
     "2001:db8:10::1",
     0},
    {"label-6to4",
     "2002:1234::2",
     {{"2002:1234::1", 0, 0, 0}, {"2001:db8:10::1", 128, 0, 0}},
     "2002:1234::1",
     0},
    {"label-teredo",
     "2001:0:abcd::2",
     {{"2001:0:1234::1", 0, 0, 0}, {"2001:db8:10::1", 128, 0, 0}},
     "2001:0:1234::1",
     0},
    {"label-6bone",
     "3ffe:1234::2",
     {{"3ffe:1234::1", 0, 0, 0}, {"2001:db8:10::1", 128, 0, 0}},
     "3ffe:1234::1",
     0},
    {"label-orchid",
     "2001:10::2",
     {{"2001:10::1", 0, 0, 0}, {"2001:db8:10::1", 128, 0, 0}},
     "2001:10::1",
     0},
    {"label-orchid2",
     "2001:20::2",
     {{"2001:20::1", 0, 0, 0}, {"2001:db8:10::1", 128, 0, 0}},
     "2001:db8:10::1",
     0},
    {"scope-link", "fe80::2", {{"fe80::1", 64, 0, 0}, {"2001:db8:10::1", 64, 0, 0}}, "fe80::1", 0},
    {"scope-link-global-only", "fe80::2", {{"2001:db8:10::1", 64, 0, 0}}, "2001:db8:10::1", 0},
    {"scope-global-link-only", "2001:db8:99::2", {{"fe80::1", 64, 0, 0}}, "fe80::1", 0},
    {"scope-site",
     "fec0:1::2",
     {{"fec0:1::1", 64, 0, 0}, {"2001:db8:10::1", 64, 0, 0}},
     "fec0:1::1",
     0},
    {"scope-before-deprecated",
     "fec0:1::2",
     {{"fec0:1::1", 64, 1, 0}, {"2001:db8:10::1", 64, 0, 0}},
     "fec0:1::1",
     0},
    {"scope-site-undersized",
     "2001:db8:99::2",
     {{"fe80::1", 64, 0, 0}, {"fec0:1::1", 64, 0, 0}},
     "fec0:1::1",
     0},
    {"link-no-cross-interface",
     "fe80::2",
     {{"fe80::1", 64, 0, 1}, {"2001:db8:10::1", 64, 0, 1}},
     "::",
     99},
    {"multicast-link",
     "ff02::123",
     {{"fe80::1", 64, 0, 0}, {"2001:db8:10::1", 64, 0, 0}},
     "fe80::1",
     0},
    {"multicast-site",
     "ff05::123",
     {{"fe80::1", 64, 0, 0}, {"2001:db8:10::1", 64, 0, 0}},
     "2001:db8:10::1",
     0},
    {"multicast-global",
     "ff0e::123",
     {{"fe80::1", 64, 0, 0}, {"2001:db8:10::1", 64, 0, 0}},
     "2001:db8:10::1",
     0},
    {"prefix-cap",
     "2001:db8:99::2",
     {{"2001:db8:99::1", 16, 0, 0}, {"2001:db8:10::1", 64, 0, 0}},
     "2001:db8:10::1",
     0},
    {"equal-newest",
     "2001:db8:99::2",
     {{"2001:db8:10::1", 64, 0, 0}, {"2001:db8:11::1", 64, 0, 0}},
     "2001:db8:11::1",
     0},
    {"deprecated-before-label",
     "fd42::2",
     {{"fd42::1", 64, 1, 0}, {"2001:db8:10::1", 64, 0, 0}},
     "2001:db8:10::1",
     0},
    {"other-link-only", "2001:db8::2", {{"fe80::1", 64, 0, 1}}, "fe80::1", 0},
    {"compat-label",
     "::192.0.2.2",
     {{"::192.0.2.1", 0, 0, 0}, {"2001:db8::1", 128, 0, 0}},
     "::192.0.2.1",
     0},
    {"deprecated-loopback", "2001:db8::2", {{"2001:db8::1", 64, 1, 0}}, "2001:db8::1", 0},
    {"compat-deprecated-label",
     "::192.0.2.2",
     {{"::192.0.2.1", 64, 1, 0}, {"2001:db8:10::1", 128, 0, 0}},
     "::192.0.2.1",
     0},
};

static unsigned sequence;

static void check(int value, const char* reason) {
    if (!value) {
        fprintf(stderr, "IPV6_SOURCE_POLICY_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static struct in6_addr address(const char* text) {
    struct in6_addr value;
    check(inet_pton(AF_INET6, text, &value) == 1, "complete test address");
    return value;
}

static size_t attribute(unsigned char* bytes, size_t at, unsigned type, const void* data,
                        unsigned size) {
    struct rtattr value = {.rta_len = (unsigned short)(4 + size), .rta_type = (unsigned short)type};
    memcpy(bytes + at, &value, 4);
    memcpy(bytes + at + 4, data, size);
    return at + RTA_ALIGN(4 + size);
}

static void request(unsigned char* bytes, size_t size) {
    struct nlmsghdr* header = (void*)bytes;
    header->nlmsg_len = (unsigned)size;
    header->nlmsg_seq = ++sequence;
    header->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "owned route control description");
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)), "owned route control port");
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, bytes, size, 0, (struct sockaddr*)&kernel, sizeof(kernel)) == (ssize_t)size,
          "complete source-policy control request");
    struct pollfd item = {.fd = fd, .events = POLLIN};
    check(poll(&item, 1, 1000) == 1 && (item.revents & POLLIN), "bounded route acknowledgment");
    _Alignas(8) unsigned char reply[8192];
    ssize_t got = recv(fd, reply, sizeof(reply), 0);
    check(got >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)), "complete route acknowledgment");
    struct nlmsghdr response;
    struct nlmsgerr result;
    memcpy(&response, reply, sizeof(response));
    memcpy(&result, reply + sizeof(response), sizeof(result));
    check(response.nlmsg_type == NLMSG_ERROR && response.nlmsg_seq == sequence &&
              response.nlmsg_len >= NLMSG_LENGTH(sizeof(result)) && !result.error,
          "successful source-policy control acknowledgment");
    check(!close(fd), "release source-policy control description");
}

static void change_address(unsigned index, const struct candidate* candidate, int remove) {
    _Alignas(8) unsigned char bytes[128] = {0};
    struct nlmsghdr* header = (void*)bytes;
    header->nlmsg_type = remove ? RTM_DELADDR : RTM_NEWADDR;
    header->nlmsg_flags = remove ? 0 : NLM_F_CREATE | NLM_F_EXCL;
    struct ifaddrmsg value = {
        .ifa_family = AF_INET6, .ifa_prefixlen = candidate->prefix, .ifa_index = index};
    memcpy(bytes + sizeof(*header), &value, sizeof(value));
    struct in6_addr ip = address(candidate->address);
    size_t size = attribute(bytes, sizeof(*header) + sizeof(value), IFA_ADDRESS, &ip, 16);
    unsigned flags = IFA_F_NODAD | IFA_F_NOPREFIXROUTE;
    size = attribute(bytes, size, IFA_FLAGS, &flags, 4);
    struct ifa_cacheinfo cache = {.ifa_prefered = candidate->deprecated ? 0 : UINT32_MAX,
                                  .ifa_valid = UINT32_MAX};
    size = attribute(bytes, size, IFA_CACHEINFO, &cache, sizeof(cache));
    request(bytes, size);
}

static void change_route(unsigned index, int remove) {
    _Alignas(8) unsigned char bytes[128] = {0};
    struct nlmsghdr* header = (void*)bytes;
    header->nlmsg_type = remove ? RTM_DELROUTE : RTM_NEWROUTE;
    header->nlmsg_flags = remove ? 0 : NLM_F_CREATE | NLM_F_EXCL;
    struct rtmsg value = {.rtm_family = AF_INET6,
                          .rtm_table = RT_TABLE_MAIN,
                          .rtm_protocol = RTPROT_BOOT,
                          .rtm_scope = RT_SCOPE_UNIVERSE,
                          .rtm_type = RTN_UNICAST};
    memcpy(bytes + sizeof(*header), &value, sizeof(value));
    size_t size = attribute(bytes, sizeof(*header) + sizeof(value), RTA_OIF, &index, 4);
    unsigned metric = 4096;
    size = attribute(bytes, size, RTA_PRIORITY, &metric, 4);
    request(bytes, size);
}

void ipv6_source_policy(void) {
    unsigned indices[2];
    int links = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(links >= 0, "interface control description");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq value = {0};
        snprintf(value.ifr_name, sizeof(value.ifr_name), "eth%u", lane);
        check(!ioctl(links, SIOCGIFINDEX, &value), "actual source-policy interface");
        indices[lane] = value.ifr_ifindex;
        value.ifr_flags = IFF_UP;
        check(!ioctl(links, SIOCSIFFLAGS, &value), "source-policy interface up");
    }
    check(!close(links), "release interface control description");
    unsigned count = 0;
    for (unsigned lane = 0; lane < 2; lane++) {
        change_route(indices[lane], 0);
        for (unsigned n = 0; n < sizeof(cases) / sizeof(cases[0]); n++) {
            const struct source_case* test = &cases[n];
            for (unsigned at = 0; at < 3 && test->candidates[at].address; at++) {
                const struct candidate* item = &test->candidates[at];
                change_address(indices[item->other ? 1 - lane : lane], item, 0);
            }
            for (unsigned bound = 0; bound < 2; bound++) {
                int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                check(fd >= 0, "real source-policy UDP description");
                if (bound) {
                    char name[8];
                    snprintf(name, sizeof(name), "eth%u", lane);
                    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
                          "actual source-policy route binding");
                }
                struct sockaddr_in6 peer = {.sin6_family = AF_INET6,
                                            .sin6_port = htons(8080),
                                            .sin6_addr = address(test->destination)};
                if (IN6_IS_ADDR_LINKLOCAL(&peer.sin6_addr) ||
                    IN6_IS_ADDR_MULTICAST(&peer.sin6_addr))
                    peer.sin6_scope_id = indices[lane];
                // Linux does not use a site/global multicast scope ID as
                // an outgoing-interface selection. Bind those observations.
                if (!bound && IN6_IS_ADDR_MULTICAST(&peer.sin6_addr)) {
                    check(!close(fd), "release unselected multicast description");
                    continue;
                }
                errno = 0;
                int result = connect(fd, (struct sockaddr*)&peer, sizeof(peer));
                int error = result < 0 ? errno : 0;
                struct sockaddr_in6 local = {0};
                socklen_t length = sizeof(local);
                check(!getsockname(fd, (struct sockaddr*)&local, &length) &&
                          length == sizeof(local),
                      "actual selected source observation");
                char text[INET6_ADDRSTRLEN];
                check(inet_ntop(AF_INET6, &local.sin6_addr, text, sizeof(text)) != NULL,
                      "selected source rendering");
                printf("IPV6_SOURCE_POLICY lane=%u case=%s bound=%u error=%d source=%s\n", lane,
                       test->name, bound, error, text);
                struct in6_addr expected = address(test->selected);
                check(error == test->error &&
                          !memcmp(&local.sin6_addr, &expected, sizeof(expected)),
                      "Linux source-policy equivalence");
                check(!close(fd), "release source-policy UDP description");
                count++;
            }
            for (unsigned at = 0; at < 3 && test->candidates[at].address; at++) {
                const struct candidate* item = &test->candidates[at];
                change_address(indices[item->other ? 1 - lane : lane], item, 1);
            }
        }
        change_route(indices[lane], 1);
    }
    printf("IPV6_SOURCE_POLICY_PASS adapters=2 observations=%u\n", count);
}

#ifdef IPV6_SOURCE_POLICY_STANDALONE
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    ipv6_source_policy();
}
#endif
