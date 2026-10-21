// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_EXPIRY"
#define IPV6_BARRIER_PROTOCOL 0x88bc
#define IPV6_BARRIER_MAGIC "IP6X"
#include "ipv6_fixture.h"

enum { cases = 16, payload_size = 1440 };

static int descriptors[2][cases];
static unsigned lookups[2][cases], heartbeats[2][cases];
static uint64_t first_epoch, lower_epoch, next_lookup;
static unsigned local_queries;

static void destination_query(int fd, unsigned type, int wanted, int wanted_error) {
    int value = -1;
    socklen_t length = sizeof(value);
    errno = 0;
    int result = getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &value, &length);
    int error = result < 0 ? errno : 0;
    printf("IPV6_EXPIRY_DESTINATION kind=%u case=%u value=%d errno=%d\n", type, local_queries++,
           value, error);
    check(result == (wanted_error ? -1 : 0) && error == wanted_error &&
              (wanted_error || (value == wanted && length == sizeof(value))),
          "owned cached destination query");
}

static void destination_contract(void) {
    for (unsigned type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
        int fd = create(type);
        destination_query(fd, type, 0, ENOTCONN);
        struct sockaddr_in6 peer = loopback(type == SOCK_RAW ? 58 : 59998);
        connect_address(fd, peer);
        destination_query(fd, type, 65536, 0);
        check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "missing0", 9) == -1 && errno == ENODEV,
              "failed device option retains query ownership");
        destination_query(fd, type, 65536, 0);
        check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3), "query device invalidation");
        destination_query(fd, type, 0, ENOTCONN);
        struct sockaddr_in6 connected;
        socklen_t capacity = sizeof(connected);
        check(!getpeername(fd, (struct sockaddr*)&connected, &capacity) &&
                  capacity == sizeof(connected) && !memcmp(&connected, &peer, sizeof(peer)),
              "query invalidation preserves the connected peer");
        unsigned char bytes[16] = {129};
        check(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes),
              "fresh output after invalidation");
        destination_query(fd, type, 65536, type == SOCK_RAW ? ENOTCONN : 0);
        connect_address(fd, peer);
        destination_query(fd, type, 65536, 0);
        int alias = dup(fd);
        check(alias >= 0 && !setsockopt(alias, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3),
              "alias shares destination invalidation");
        destination_query(fd, type, 0, ENOTCONN);
        connect_address(fd, peer);
        destination_query(alias, type, 65536, 0);
        check(!close(fd), "destination owner alias release");
        destination_query(alias, type, 65536, 0);
        struct sockaddr_in6 unspecified = {0};
        check(!connect(alias, (struct sockaddr*)&unspecified, 2), "destination disconnect");
        destination_query(alias, type, 0, ENOTCONN);
        check(!close(alias), "last destination owner release");
    }
    puts("IPV6_EXPIRY_DESTINATION_PASS queries=20 transports=2 aliases=2");
}

static unsigned kind(unsigned number) {
    return number < 8 ? SOCK_DGRAM : SOCK_RAW;
}

static void payload(unsigned char* bytes, unsigned length, unsigned lane, unsigned number,
                    unsigned stage) {
    for (unsigned n = 0; n < length; n++)
        bytes[n] = n * 29 + number * 7 + stage * 11 + lane;
    unsigned offset = kind(number) == SOCK_RAW ? 4 : 0;
    if (offset) {
        bytes[0] = 129;
        bytes[1] = bytes[2] = bytes[3] = 0;
    }
    memcpy(bytes + offset, "P6EX", 4);
    bytes[offset + 4] = number;
    bytes[offset + 5] = stage;
    bytes[offset + 6] = lane;
    bytes[offset + 7] = 0;
}

static int open_path(unsigned lane, unsigned number) {
    int fd = create(kind(number));
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "expiry interface ownership");
    option(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, 2);
    if (kind(number) == SOCK_DGRAM)
        option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    int scoped = number % 8 >= 4;
    bind_address(fd, address(lane, 2, kind(number) == SOCK_DGRAM ? 49000 + number : 0, scoped));
    connect_address(
        fd, address(lane, 32 + number, kind(number) == SOCK_DGRAM ? 50000 + number : 58, scoped));
    return fd;
}

static int expected_mtu(unsigned number, unsigned stage) {
    unsigned role = number % 4;
    if (role == 3 || stage == 0 || stage == 6 || (stage == 5 && role != 2))
        return 1500;
    if (stage >= 3 && (role == 1 || role == 2))
        return 1280;
    return role < 2 ? 1400 : 1500;
}

static void sample(unsigned lane, unsigned number, unsigned stage) {
    unsigned role = number % 4;
    int wanted_mtu = expected_mtu(number, stage);
    int asynchronous = ((stage == 1 && role < 2) || (stage == 3 && role < 3)) ? EMSGSIZE : 0;
    int fd = descriptors[lane][number];
    int error = get(fd, SOL_SOCKET, SO_ERROR);
    // A connected Linux socket can expose its old destination before the next
    // send revalidates that destination. Test expiry through the actual send.
    int before = stage < 5 ? get(fd, IPPROTO_IPV6, IPV6_MTU) : -1;
    unsigned char bytes[payload_size];
    payload(bytes, sizeof(bytes), lane, number, stage);
    if (stage == 2)
        option(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, 3);
    errno = 0;
    ssize_t result = send(fd, bytes, sizeof(bytes), 0);
    int send_error = result < 0 ? errno : 0;
    if (stage == 2)
        option(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, 2);
    int after = get(fd, IPPROTO_IPV6, IPV6_MTU);
    int pending = get(fd, SOL_SOCKET, SO_ERROR);
    printf("IPV6_EXPIRY_SAMPLE lane=%u case=%u stage=%u before=%d after=%d result=%ld errno=%d "
           "async=%d pending=%d\n",
           lane, number, stage, before, after, (long)result, send_error, error, pending);
    fflush(stdout);
    check(error == asynchronous && pending == 0, "expiry error consumption");
    // Raw output looks up a fresh route without replacing its connected query
    // destination. Its last learned metric remains readable after wire expiry.
    int queried_mtu = kind(number) == SOCK_RAW && stage >= 5 && role != 3
                          ? (role == 0 ? 1400 : 1280)
                          : wanted_mtu;
    check(after == queried_mtu, "expiry retained destination MTU after actual send");
    int emitted = stage == 2 || wanted_mtu == 1500;
    check(emitted ? result == payload_size && !send_error : result == -1 && send_error == EMSGSIZE,
          "expiry actual send result");
    if (stage < 5)
        check(before == wanted_mtu, "unexpired or original path MTU");
}

static void drain_packets(void) {
    unsigned char bytes[2048];
    for (unsigned lane = 0; lane < 2; lane++) {
        while (recv(packets[lane], bytes, sizeof(bytes), MSG_DONTWAIT) >= 0) {
        }
        check(errno == EAGAIN, "expiry packet queue drain");
    }
}

static void wait_until(uint64_t deadline, int lowered, int first_expired) {
    while (now() < deadline) {
        uint64_t current = now();
        if (current >= next_lookup) {
            for (unsigned lane = 0; lane < 2; lane++) {
                for (unsigned number = 0; number < cases; number++) {
                    unsigned role = number % 4;
                    uint64_t epoch = role == 2 ? lower_epoch : first_epoch;
                    if (role != 3 && (role != 2 || lowered) && current >= epoch + 597000000000ULL)
                        continue;
                    int wanted = expected_mtu(number, first_expired ? 5 : lowered ? 3 : 1);
                    int fd = descriptors[lane][number];
                    check(get(fd, IPPROTO_IPV6, IPV6_MTU) == wanted, "periodic PMTU lookup");
                    lookups[lane][number]++;
                    if (role != 0) {
                        unsigned char bytes[16];
                        payload(bytes, sizeof(bytes), lane, number, 250);
                        check(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes),
                              "ordinary traffic does not renew a PMTU deadline");
                        heartbeats[lane][number]++;
                    }
                }
            }
            next_lookup = current + 5000000000ULL;
        }
        drain_packets();
        struct timespec pause = {.tv_nsec = 100000000};
        check(!nanosleep(&pause, 0), "real expiry observation wait");
    }
}

int main(int argc, char** argv) {
    destination_contract();
    if ((argc == 2 && !strcmp(argv[1], "--local-only")) || getenv("AXIOM64_IPV6_LOCAL_ONLY"))
        return 0;
    int control = fixture_interfaces();
    for (unsigned lane = 0; lane < 2; lane++) {
        barrier(lane, 1);
        for (unsigned number = 0; number < cases; number++) {
            descriptors[lane][number] = open_path(lane, number);
            sample(lane, number, 0);
        }
        barrier(lane, 2);
    }
    first_epoch = now();
    next_lookup = first_epoch + 5000000000ULL;
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned number = 0; number < cases; number++)
            sample(lane, number, 1);
    wait_until(first_epoch + 20000000000ULL, 0, 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned number = 0; number < cases; number++)
            sample(lane, number, 2);
        barrier(lane, 3);
    }
    lower_epoch = now();
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned number = 0; number < cases; number++)
            sample(lane, number, 3);
    wait_until(first_epoch + 598000000000ULL, 1, 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned number = 0; number < cases; number++)
            sample(lane, number, 4);
        barrier(lane, 4);
    }
    wait_until(first_epoch + 602000000000ULL, 1, 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned number = 0; number < cases; number++)
            sample(lane, number, 5);
        barrier(lane, 5);
    }
    wait_until(lower_epoch + 602000000000ULL, 1, 1);
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned number = 0; number < cases; number++) {
            sample(lane, number, 6);
            printf("IPV6_EXPIRY_LOOKUPS lane=%u case=%u reads=%u sends=%u\n", lane, number,
                   lookups[lane][number], heartbeats[lane][number]);
            check(lookups[lane][number] >= 115, "complete ten-minute lookup observation");
            check(!close(descriptors[lane][number]), "expiry description release");
        }
        barrier(lane, 6);
        close(packets[lane]);
    }
    close(control);
    puts("IPV6_EXPIRY_PASS adapters=2 paths=32 stages=7 lifetime_seconds=600 "
         "lower_delay_seconds=20");
}
