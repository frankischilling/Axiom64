// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_CACHED"
#define IPV6_BARRIER_PROTOCOL 0x88c6
#define IPV6_BARRIER_MAGIC "IP6K"
#include "ipv6_fixture.h"

static int opened(unsigned lane, unsigned type, unsigned scope, unsigned port) {
    int fd = create(type);
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1), "owned device");
    if (type == SOCK_DGRAM)
        option(fd, 41, IPV6_V6ONLY, 1);
    option(fd, 41, IPV6_RECVERR, 1);
    option(fd, 41, IPV6_MTU_DISCOVER, 2);
    bind_address(fd, address(lane, 2, port, scope));
    return fd;
}

static int metric(int fd) {
    int value = -1;
    socklen_t size = sizeof(value);
    errno = 0;
    int result = getsockopt(fd, 41, IPV6_MTU, &value, &size);
    check(!result || (result == -1 && errno == ENOTCONN), "destination metric result");
    return result ? -ENOTCONN : value;
}

static void host_route(unsigned lane, unsigned scope) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "host route control");

    struct {
        struct nlmsghdr header;
        struct rtmsg route;
        struct rtattr destination;
        struct in6_addr address;
        struct rtattr interface;
        unsigned index;
        struct rtattr priority;
        unsigned metric;
    } message = {0};

    message.header = (struct nlmsghdr){sizeof(message), RTM_NEWROUTE,
                                       NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 1, 0};
    message.route = (struct rtmsg){.rtm_family = AF_INET6,
                                   .rtm_dst_len = 128,
                                   .rtm_table = RT_TABLE_MAIN,
                                   .rtm_protocol = RTPROT_STATIC,
                                   .rtm_scope = RT_SCOPE_LINK,
                                   .rtm_type = RTN_UNICAST};
    message.destination = (struct rtattr){20, RTA_DST};
    message.address = address(lane, 160, 0, scope).sin6_addr;
    message.interface = (struct rtattr){8, RTA_OIF};
    message.index = indices[lane];
    message.priority = (struct rtattr){8, RTA_PRIORITY};
    message.metric = 100 + lane;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &message, sizeof(message), 0, (void*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "actual host route request");
    unsigned char reply[256];
    long size = recv(fd, reply, sizeof(reply), 0);
    struct nlmsgerr error;
    check(size >= (long)NLMSG_LENGTH(sizeof(error)) &&
              ((struct nlmsghdr*)reply)->nlmsg_type == NLMSG_ERROR,
          "host route acknowledgement");
    memcpy(&error, NLMSG_DATA((struct nlmsghdr*)reply), sizeof(error));
    errno = -error.error;
    check(!error.error, "host route accepted");
    check(!close(fd), "retire host route control");
}

static unsigned routing_header(unsigned char* routing, unsigned lane, unsigned scope, unsigned mode,
                               unsigned first) {
    unsigned size = mode < 2 ? 24 : mode == 2 ? 40 : 64;
    memset(routing, 0, 64);
    routing[0] = 250;
    routing[1] = size / 8 - 1;
    routing[2] = mode ? 4 : 2;
    routing[3] = mode == 1 ? 0 : mode == 3 ? 2 : 1;
    routing[4] = mode ? routing[3] : 0;
    for (unsigned n = 0; n <= (mode ? routing[4] : 0); n++) {
        struct in6_addr value = address(lane, 77 + n, 0, scope).sin6_addr;
        memcpy(routing + 8 + n * 16, &value, 16);
    }
    struct in6_addr target = address(lane, first, 0, scope).sin6_addr;
    memcpy(routing + 8 + (mode ? routing[3] * 16 : 0), &target, 16);
    if (mode == 3) {
        routing[56] = 30;
        routing[57] = 6;
        memset(routing + 58, 0x99, 6);
    }
    return size;
}

static void hex(const unsigned char* bytes, unsigned size) {
    for (unsigned n = 0; n < size; n++)
        printf("%02x", bytes[n]);
}

int main(void) {
    int control = fixture_interfaces();
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned phase = 1, sequence = 0;
        for (unsigned scope = 0; scope < 2; scope++) {
            host_route(lane, scope);
            int seed = opened(lane, SOCK_DGRAM, scope, 55000 + scope);
            connect_address(seed, address(lane, 128, 57000, scope));
            unsigned char payload[32];
            for (unsigned n = 0; n < sizeof(payload); n++)
                payload[n] = n * 19 + lane;
            barrier(lane, phase++);
            check(send(seed, payload, sizeof(payload), 0) == sizeof(payload),
                  "seed first-hop path");
            barrier(lane, phase++);
            readable(seed, POLLERR);
            check(metric(seed) == 1400 && get(seed, SOL_SOCKET, SO_ERROR) == EMSGSIZE,
                  "actual first-hop PMTU learned");
            option(seed, 41, IPV6_RECVERR, 0);
            check(!close(seed), "retire seed without removing its route exception");
            for (unsigned type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
                for (unsigned format = 0; format < 2; format++) {
                    unsigned mode = format ? (scope && type == SOCK_DGRAM ? 3
                                              : type == SOCK_RAW          ? 2
                                                                          : 1)
                                           : 0;
                    for (unsigned variant = 0; variant < 8; variant++, sequence++) {
                        unsigned first = variant == 0 ? 176 : variant == 6 ? 160 : 128;
                        int fd = opened(lane, type, scope, 56000 + sequence);
                        unsigned char routing[64], stored[64];
                        unsigned size = routing_header(routing, lane, scope, mode, first);
                        check(!setsockopt(fd, 41, IPV6_RTHDR, routing, size),
                              "stored Routing header");
                        struct sockaddr_in6 final =
                            address(lane, 71, type == SOCK_RAW ? 58 : 57000, scope);
                        if (!scope)
                            check(inet_pton(AF_INET6, lane ? "2001:db8:92::47" : "2001:db8:91::47",
                                            &final.sin6_addr) == 1,
                                  "requested off-link final destination");
                        if (variant != 2)
                            connect_address(fd, final);
                        if (variant == 5)
                            option(fd, 41, IPV6_TCLASS, 0);
                        if (variant == 3 && format)
                            option(fd, 41, IPV6_TCLASS, 0x25);
                        else if (variant == 3)
                            check(!setsockopt(fd, 41, IPV6_RTHDR, routing, size),
                                  "replace cached option");
                        int alias = dup(fd);
                        check(alias >= 0 && !close(fd), "shared cached description");
                        fd = alias;
                        int before = metric(fd);

                        union {
                            struct cmsghdr align;
                            unsigned char bytes[96];
                        } ancillary;

                        memset(&ancillary, 0xa5, sizeof(ancillary));
                        struct iovec vector = {payload, sizeof(payload)};
                        struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
                        if (variant == 2 || variant == 4) {
                            message.msg_name = &final;
                            message.msg_namelen = sizeof(final);
                        }
                        if (variant == 5 || variant == 7) {
                            message.msg_control = ancillary.bytes;
                            struct cmsghdr* header = (void*)ancillary.bytes;
                            memset(header, 0, sizeof(*header));
                            header->cmsg_level = 41;
                            header->cmsg_type = variant == 5 ? IPV6_HOPLIMIT : IPV6_RTHDR;
                            unsigned data_size = variant == 5 ? 4 : 24;
                            header->cmsg_len = CMSG_LEN(data_size);
                            message.msg_controllen = CMSG_SPACE(data_size);
                            if (variant == 5) {
                                int hops = 55;
                                memcpy(CMSG_DATA(header), &hops, 4);
                            } else {
                                unsigned char alternate[64];
                                routing_header(alternate, lane, scope, 0, 192);
                                memcpy(CMSG_DATA(header), alternate, 24);
                            }
                        }
                        unsigned char original[96];
                        memcpy(original, ancillary.bytes, sizeof(original));
                        for (unsigned n = 0; n < sizeof(payload); n++)
                            payload[n] = n * 19 + sequence * 7 + lane;
                        if (type == SOCK_RAW) {
                            payload[0] = 129;
                            payload[1] = payload[2] = payload[3] = 0;
                        }
                        barrier(lane, phase++);
                        errno = 0;
                        long result = sendmsg(fd, &message, 0);
                        int error = result < 0 ? errno : 0;
                        check(result == sizeof(payload), "original cached Routing send");
                        unsigned char oversized[1600] = {0};
                        struct iovec large = {oversized, sizeof(oversized)};
                        message.msg_iov = &large;
                        errno = 0;
                        check(sendmsg(fd, &message, 0) == -1 && errno == EMSGSIZE,
                              "Routing-bearing local MTU error");
                        struct sockaddr_in6 failed;
                        unsigned char error_controls[96];
                        memset(&failed, 0xa5, sizeof(failed));
                        memset(error_controls, 0xa5, sizeof(error_controls));
                        struct msghdr failure = {.msg_name = &failed,
                                                 .msg_namelen = sizeof(failed),
                                                 .msg_control = error_controls,
                                                 .msg_controllen = sizeof(error_controls)};
                        check(recvmsg(fd, &failure, MSG_ERRQUEUE | MSG_DONTWAIT) == 0 &&
                                  failure.msg_namelen == sizeof(failed),
                              "actual Routing local error dequeue");
                        printf("IPV6_CACHED_ERROR lane=%u case=%u flags=%d length=%u name=", lane,
                               sequence, failure.msg_flags, (unsigned)failure.msg_controllen);
                        hex((const unsigned char*)&failed, sizeof(failed));
                        printf(" control=");
                        hex(error_controls, sizeof(error_controls));
                        printf("\n");
                        barrier(lane, phase++);
                        check(!memcmp(original, ancillary.bytes, sizeof(original)),
                              "original ancillary unchanged");
                        int after = metric(fd);
                        memset(stored, 0xa5, sizeof(stored));
                        socklen_t copied = sizeof(stored);
                        check(!getsockopt(fd, 41, IPV6_RTHDR, stored, &copied) && copied == size &&
                                  !memcmp(stored, routing, size),
                              "shared sticky bytes unchanged");
                        if (variant != 2) {
                            struct sockaddr_in6 peer;
                            socklen_t capacity = sizeof(peer);
                            check(!getpeername(fd, (void*)&peer, &capacity) &&
                                      capacity == sizeof(peer) &&
                                      !memcmp(&peer.sin6_addr, &final.sin6_addr, 16) &&
                                      peer.sin6_scope_id == final.sin6_scope_id,
                                  "requested peer survives cached output");
                        }
                        printf(
                            "IPV6_CACHED_CASE lane=%u case=%u type=%u scope=%u mode=%u variant=%u "
                            "result=%ld errno=%d before=%d after=%d routing=",
                            lane, sequence, type, scope, mode, variant, result, error, before,
                            after);
                        hex(routing, sizeof(routing));
                        printf(" control=");
                        hex(original, sizeof(original));
                        printf("\n");
                        check(!close(fd), "retire cached description");
                    }
                }
            }
        }
        check(sequence == 64 && phase == 133, "complete cached route inventory");
    }
    check(!close(control), "retire fixture control");
    for (unsigned lane = 0; lane < 2; lane++)
        check(!close(packets[lane]), "retire packet socket");
    puts("IPV6_CACHED_PASS adapters=2 cases=128 variants=8 scopes=2 transports=2");
}
