// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdatomic.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static uint64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        exit(2);
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_PRESSURE_FAIL observer line=%d errno=%d\n", __LINE__, errno);     \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
static int native_capture;
static atomic_int stop;
static int observers[2];
static unsigned indices[2], observed[2], ipv4_frames[2];
static pthread_t observer;

static void drain(unsigned lane) {
    for (;;) {
        uint8_t frame[2048];
        struct sockaddr_ll source;
        socklen_t size = sizeof(source);
        ssize_t length = recvfrom(observers[lane], frame, sizeof(frame), MSG_DONTWAIT,
                                  (struct sockaddr*)&source, &size);
        if (length < 0) {
            CHECK(errno == EAGAIN);
            return;
        }
        CHECK(length >= 14 && source.sll_ifindex == (int)indices[lane]);
        observed[lane]++;
        if (frame[12] != 8 || frame[13] != 0) {
            uint64_t digest = UINT64_C(0xcbf29ce484222325);
            for (ssize_t at = 0; at < length; at++)
                digest = (digest ^ frame[at]) * UINT64_C(0x100000001b3);
            printf("PRESSURE_LINK_FRAME lane=%u index=%u length=%zd kind=%u ether_type=%02x%02x "
                   "hash=%016llx monotonic_ms=%llu\n",
                   lane, indices[lane], length, source.sll_pkttype, frame[12], frame[13],
                   (unsigned long long)digest, (unsigned long long)milliseconds());
            continue;
        }
        uint64_t digest = UINT64_C(0xcbf29ce484222325);
        for (ssize_t at = 0; at < length; at++)
            digest = (digest ^ frame[at]) * UINT64_C(0x100000001b3);
        ipv4_frames[lane]++;
        printf(
            "PRESSURE_FRAME lane=%u index=%u length=%zd kind=%u hash=%016llx monotonic_ms=%llu\n",
            lane, indices[lane], length, source.sll_pkttype, (unsigned long long)digest,
            (unsigned long long)milliseconds());
    }
}

static void* collect(void* unused) {
    (void)unused;
    while (!atomic_load(&stop)) {
        drain(0);
        drain(1);
        CHECK(usleep(2000) == 0);
    }
    drain(0);
    drain(1);
    return NULL;
}

static void capture_start(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        indices[lane] = if_nametoindex(name);
        // Outgoing packets are delivered only to ETH_P_ALL observers.
        unsigned protocol = 3;
        observers[lane] =
            socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(protocol));
        int capacity = 131072, actual;
        socklen_t capacity_size = sizeof(actual);
        CHECK(observers[lane] >= 0 &&
              setsockopt(observers[lane], SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity)) ==
                  0 &&
              getsockopt(observers[lane], SOL_SOCKET, SO_RCVBUF, &actual, &capacity_size) == 0 &&
              capacity_size == sizeof(actual) && actual == capacity * 2);
        struct sockaddr_ll address = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(protocol),
                                      .sll_ifindex = (int)indices[lane]};
        CHECK(observers[lane] >= 0 && indices[lane] &&
              bind(observers[lane], (struct sockaddr*)&address, sizeof(address)) == 0);
        printf("PRESSURE_CAPTURE_READY lane=%u index=%u\n", lane, indices[lane]);
    }
    CHECK(pthread_create(&observer, NULL, collect, NULL) == 0);
}

static void capture_stop(void) {
    CHECK(usleep(100000) == 0);
    atomic_store(&stop, 1);
    CHECK(pthread_join(observer, NULL) == 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        // Stop future arrivals before draining packets queued after the collector.
        struct sockaddr_ll retired = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(0x88b6),
                                      .sll_ifindex = (int)indices[lane]};
        CHECK(bind(observers[lane], (struct sockaddr*)&retired, sizeof(retired)) == 0);
        drain(lane);
        unsigned statistics[2];
        socklen_t size = sizeof(statistics);
        CHECK(getsockopt(observers[lane], 263, 6, statistics, &size) == 0 &&
              size == sizeof(statistics) && statistics[0] == observed[lane] && !statistics[1]);
        printf("PRESSURE_CAPTURE_PASS lane=%u index=%u packets=%u dropped=%u ipv4=%u\n", lane,
               indices[lane], statistics[0], statistics[1], ipv4_frames[lane]);
        CHECK(close(observers[lane]) == 0);
    }
}

static int configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &value, sizeof(value));
        if (ioctl(fd, SIOCSIFADDR, &request))
            return -1;
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        if (ioctl(fd, SIOCSIFNETMASK, &request) || ioctl(fd, SIOCGIFFLAGS, &request))
            return -1;
        request.ifr_flags |= IFF_UP;
        if (ioctl(fd, SIOCSIFFLAGS, &request))
            return -1;
    }
    return close(fd);
}

static bool external = true;
static int companions[2] = {-1, -1};

static void companion_exchange(unsigned lane, unsigned step) {
    unsigned char bytes[16];
    for (unsigned at = 0; at < sizeof(bytes); at++)
        bytes[at] = (unsigned char)((at * 29) ^ (lane * 53) ^ (step * 97));
    CHECK(send(companions[lane], bytes, sizeof(bytes), MSG_NOSIGNAL) == sizeof(bytes));
    size_t received = 0;
    while (received < sizeof(bytes)) {
        ssize_t count = recv(companions[lane], bytes + received, sizeof(bytes) - received, 0);
        CHECK(count > 0 && (size_t)count <= sizeof(bytes) - received);
        received += (size_t)count;
    }
    for (unsigned at = 0; at < sizeof(bytes); at++)
        CHECK(bytes[at] == (unsigned char)((at * 29) ^ (lane * 53) ^ (step * 97) ^ 41));
    int error = -1;
    socklen_t size = sizeof(error);
    CHECK(getsockopt(companions[lane], SOL_SOCKET, SO_ERROR, &error, &size) == 0 && !error);
    printf("TCP_PRESSURE_COMPANION_PASS lane=%u step=%u bytes=16 monotonic_ms=%llu\n", lane, step,
           (unsigned long long)milliseconds());
}

static void companions_start(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        companions[lane] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct timeval timeout = {20, 0};
        int enabled = 1;
        struct sockaddr_in local = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        struct sockaddr_in peer = {.sin_family = AF_INET,
                                   .sin_port = htons(46000 + lane),
                                   .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
        CHECK(
            companions[lane] >= 0 &&
            setsockopt(companions[lane], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(companions[lane], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(companions[lane], IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) ==
                0 &&
            bind(companions[lane], (struct sockaddr*)&local, sizeof(local)) == 0 &&
            connect(companions[lane], (struct sockaddr*)&peer, sizeof(peer)) == 0);
        companion_exchange(lane, 0);
    }
}

static void companions_stop(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned char byte;
        CHECK(shutdown(companions[lane], SHUT_WR) == 0 &&
              recv(companions[lane], &byte, 1, 0) == 0 && close(companions[lane]) == 0);
    }
}

static int pair(int result[2], const char** failed) {
    int listener = -1, client = -1, server = -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    struct timeval timeout = {2, 0};
#define TRY(label, expression)                                                                     \
    do {                                                                                           \
        *failed = label;                                                                           \
        if (!(expression))                                                                         \
            goto out;                                                                              \
    } while (0)
    TRY("listener-socket", (listener = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
    TRY("listener-bind", bind(listener, (struct sockaddr*)&address, sizeof(address)) == 0);
    TRY("listener-listen", listen(listener, 2) == 0);
    TRY("listener-name", getsockname(listener, (struct sockaddr*)&address, &length) == 0);
    TRY("client-socket", (client = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
    TRY("client-timeout",
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    TRY("client-connect", connect(client, (struct sockaddr*)&address, sizeof(address)) == 0);
    TRY("server-accept", (server = accept(listener, NULL, NULL)) >= 0);
    TRY("server-timeout",
        setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    TRY("client-receive-timeout",
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    close(listener);
    result[0] = client;
    result[1] = server;
    return 0;
out: {
    int saved = errno;
    if (listener >= 0)
        close(listener);
    if (client >= 0)
        close(client);
    if (server >= 0)
        close(server);
    errno = saved;
    return -1;
}
#undef TRY
}

static int aborted_cycles(void) {
    int control = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    if (control < 0 || bind(control, (struct sockaddr*)&address, sizeof(address)) ||
        getsockname(control, (struct sockaddr*)&address, &length))
        return 2;
    // A bound, unlistened port refuses connections and excludes accidental self-connects.
    int retained = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {2, 0};
    if (retained < 0 || setsockopt(retained, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
        return 2;
    for (unsigned cycle = 0; cycle < 1280; cycle++) {
        if (connect(retained, (struct sockaddr*)&address, sizeof(address)) != -1 ||
            errno != ECONNREFUSED)
            return 2;
        int error = -1;
        socklen_t size = sizeof(error);
        if (getsockopt(retained, SOL_SOCKET, SO_ERROR, &error, &size) || error)
            return 2;
        int pending = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (pending < 0 || connect(pending, (struct sockaddr*)&address, sizeof(address)) != -1 ||
            (errno != EINPROGRESS && errno != ECONNREFUSED) || close(pending))
            return 2;
    }
    if (close(retained) || close(control))
        return 2;
    puts("TCP_PRESSURE_ABORTED_PASS retained=1280 detached=1280");
    return 0;
}

static int loopback_listener(struct sockaddr_in* address) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    *address =
        (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr*)address, sizeof(*address)) == 0 && listen(fd, 2) == 0);
    socklen_t length = sizeof(*address);
    CHECK(getsockname(fd, (struct sockaddr*)address, &length) == 0);
    struct timeval timeout = {2, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}

static int loopback_client(const struct sockaddr_in* address) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct timeval timeout = {2, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
          setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(connect(fd, (const struct sockaddr*)address, sizeof(*address)) == 0);
    return fd;
}

static void reset_peer(int fd) {
    unsigned char value;
    CHECK(recv(fd, &value, 1, 0) == -1 && errno == ECONNRESET && close(fd) == 0);
}

static void listener_cycles(void) {
    struct sockaddr_in independent_address;
    int independent = loopback_listener(&independent_address);
    int control = loopback_client(&independent_address);
    int control_peer = accept(independent, NULL, NULL);
    CHECK(control_peer >= 0);
    struct timeval timeout = {2, 0};
    CHECK(setsockopt(control_peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    for (unsigned mode = 0; mode < 4; mode++) {
        for (unsigned cycle = 0; cycle < 1280; cycle++) {
            struct sockaddr_in address;
            int parent = loopback_listener(&address);
            int pending = loopback_client(&address);
            if (mode < 2) {
                if (mode == 1)
                    CHECK(shutdown(parent, SHUT_RDWR) == 0);
                CHECK(close(parent) == 0);
                reset_peer(pending);
            } else if (mode == 2) {
                int accepted = accept(parent, NULL, NULL);
                CHECK(accepted >= 0 && close(parent) == 0);
                unsigned char request = (unsigned char)cycle;
                CHECK(send(pending, &request, 1, MSG_NOSIGNAL) == 1);
                struct pollfd ready = {.fd = accepted, .events = POLLIN};
                CHECK(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN));
                unsigned char value;
                CHECK(recv(accepted, &value, 1, MSG_PEEK) == 1 && value == request);
                // An accepted child survives its listener; unread close must reset.
                CHECK(close(accepted) == 0);
                reset_peer(pending);
            } else {
                CHECK(listen(parent, 1) == 0);
                int clients[4] = {pending};
                unsigned count = 1;
                bool blocked = false;
                while (count < 4 && !blocked) {
                    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                    CHECK(fd >= 0);
                    clients[count++] = fd;
                    int result = connect(fd, (struct sockaddr*)&address, sizeof(address));
                    CHECK(!result || (result == -1 && errno == EINPROGRESS));
                    struct pollfd ready = {.fd = fd, .events = POLLOUT};
                    result = poll(&ready, 1, 1);
                    CHECK(result >= 0 && !(ready.revents & POLLERR));
                    blocked = result == 0;
                    if (!blocked) {
                        int error = -1;
                        socklen_t length = sizeof(error);
                        CHECK((ready.revents & POLLOUT) &&
                              getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error);
                    }
                }
                CHECK(blocked && close(parent) == 0);
                // Completed children reset; the still-pending description aborts on close.
                for (unsigned at = 0; at + 1 < count; at++)
                    reset_peer(clients[at]);
                CHECK(close(clients[count - 1]) == 0);
            }
            if (cycle % 128 == 127) {
                unsigned char request = (unsigned char)(cycle ^ mode), value;
                CHECK(send(control, &request, 1, MSG_NOSIGNAL) == 1 &&
                      recv(control_peer, &value, 1, 0) == 1 && value == request &&
                      send(control_peer, &value, 1, MSG_NOSIGNAL) == 1 &&
                      recv(control, &value, 1, 0) == 1 && value == request);
            }
        }
        printf("TCP_PRESSURE_LISTENER_MODE_PASS mode=%u cycles=1280 independent_bytes=10\n", mode);
    }
    unsigned char request = 'x';
    CHECK(send(control, &request, 1, MSG_NOSIGNAL) == 1);
    struct pollfd ready = {.fd = control_peer, .events = POLLIN};
    CHECK(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN) && close(control_peer) == 0);
    reset_peer(control);
    CHECK(close(independent) == 0);
    puts("TCP_PRESSURE_LISTENER_PASS modes=4 cycles=5120 independent_bytes=40");
}

static int pressure(unsigned phase, bool native) {
    uint64_t began = milliseconds();
    unsigned cycles = 0;
    const char* failed = "none";
    int tcp_error = 0;
    for (; cycles < 1280; cycles++) {
        int sockets[2];
        if (pair(sockets, &failed)) {
            tcp_error = errno;
            break;
        }
        unsigned char value = 0, request = (unsigned char)(cycles ^ (phase * 73));
        unsigned char reply = request ^ 0xa5;
        if (send(sockets[0], &request, 1, MSG_NOSIGNAL) != 1 ||
            recv(sockets[1], &value, 1, 0) != 1 || value != request ||
            send(sockets[1], &reply, 1, MSG_NOSIGNAL) != 1 || recv(sockets[0], &value, 1, 0) != 1 ||
            value != reply || shutdown(sockets[0], SHUT_WR) ||
            recv(sockets[1], &value, 1, 0) != 0 || shutdown(sockets[1], SHUT_WR) ||
            recv(sockets[0], &value, 1, 0) != 0 || close(sockets[0]) || close(sockets[1])) {
            perror("TCP_PRESSURE_BAD_STREAM");
            return 2;
        }
        if (cycles % 128 == 127)
            printf("TCP_PRESSURE_PROGRESS phase=%u cycles=%u milliseconds=%llu\n", phase,
                   cycles + 1, (unsigned long long)(milliseconds() - began));
    }
    if (usleep(100000))
        return 2;
    if (external)
        for (unsigned lane = 0; lane < 2; lane++)
            companion_exchange(lane, phase + 1);
    int datagrams[32];
    unsigned udp = 0;
    int udp_error = 0;
    for (; udp < 32; udp++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            udp_error = errno;
            break;
        }
        datagrams[udp] = fd;
        unsigned lane = udp & 1;
        struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(external ? 0x0a170102 + (lane << 8) : INADDR_LOOPBACK)};
        socklen_t length = sizeof(address);
        struct timeval timeout = {2, 0};
        unsigned char value[16],
            request[16] = {'U', (unsigned char)phase, (unsigned char)udp, (unsigned char)lane};
        for (unsigned at = 4; at < sizeof(request); at++)
            request[at] = (unsigned char)((at * 29) ^ (phase * 53) ^ (udp * 97) ^ (lane * 41));
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            bind(fd, (struct sockaddr*)&address, sizeof(address)) ||
            getsockname(fd, (struct sockaddr*)&address, &length)) {
            perror("TCP_PRESSURE_BAD_UDP_SETUP");
            return 2;
        }
        if (external) {
            address.sin_addr.s_addr = htonl(0x0a170101 + (lane << 8));
            address.sin_port = htons(47000 + lane * 100 + udp);
        }
        struct sockaddr_in source;
        socklen_t size = sizeof(source);
        if (sendto(fd, request, sizeof(request), 0, (struct sockaddr*)&address, sizeof(address)) !=
                sizeof(request) ||
            recvfrom(fd, value, sizeof(value), 0, (struct sockaddr*)&source, &size) !=
                sizeof(value) ||
            size != sizeof(source) || source.sin_family != AF_INET ||
            source.sin_addr.s_addr != address.sin_addr.s_addr ||
            source.sin_port != address.sin_port) {
            perror("TCP_PRESSURE_BAD_UDP");
            return 2;
        }
        for (unsigned at = 0; at < sizeof(value); at++)
            CHECK(value[at] == (unsigned char)(request[at] ^ (external ? 0x80 : 0)));
        printf("TCP_PRESSURE_UDP_PASS phase=%u index=%u lane=%u bytes=16 monotonic_ms=%llu\n",
               phase, udp, lane, (unsigned long long)milliseconds());
    }
    printf("TCP_PRESSURE_RESULT phase=%u cycles=%u target=1280 stage=%s tcp_error=%d udp=%u "
           "udp_error=%d "
           "milliseconds=%llu\n",
           phase, cycles, tcp_error ? failed : "none", tcp_error, udp, udp_error,
           (unsigned long long)(milliseconds() - began));
    for (unsigned i = 0; i < udp; i++)
        close(datagrams[i]);
    bool count = native
                     ? cycles == 1280 && !tcp_error
                     : cycles == (external ? 1021u : 1023u) && !strcmp(failed, "client-connect") &&
                           (tcp_error == EINPROGRESS || tcp_error == ENOBUFS);
    return count && udp == 32 ? 0 : 1;
}

int main(int argc, char** argv) {
    bool native = false, expiry = true;
    for (int at = 1; at < argc; at++) {
        if (!strcmp(argv[at], "--native"))
            native = true;
        else if (!strcmp(argv[at], "--expiry"))
            expiry = true;
        else if (!strcmp(argv[at], "--quick"))
            expiry = false;
        else if (!strcmp(argv[at], "--loopback-only"))
            external = false;
        else
            return 2;
    }
    setbuf(stdout, NULL);
    signal(SIGPIPE, SIG_IGN);
    alarm(expiry ? 240 : 90);
    printf("TCP_PRESSURE_MODE native=%u expiry=%u external=%u\n", native, expiry, external);
    if (external) {
        native_capture = native;
        if (!native)
            CHECK(configure() == 0);
        puts("TCP_PRESSURE_CONFIG_PASS nics=2");
        capture_start();
        companions_start();
    }
    listener_cycles();
    if (aborted_cycles()) {
        perror("TCP_PRESSURE_FAIL aborted-cycles");
        return 2;
    }
    if (pressure(0, native))
        return 1;
    if (expiry) {
        uint64_t began = milliseconds();
        printf("TCP_PRESSURE_EXPIRY_BEGIN start_ms=%llu required_ms=120000\n",
               (unsigned long long)began);
        while (milliseconds() - began < 120000)
            if (usleep(10000))
                return 2;
        uint64_t ended = milliseconds();
        printf("TCP_PRESSURE_EXPIRY_END start_ms=%llu end_ms=%llu elapsed_ms=%llu\n",
               (unsigned long long)began, (unsigned long long)ended,
               (unsigned long long)(ended - began));
        if (pressure(1, native))
            return 1;
    }
    if (external) {
        companions_stop();
        capture_stop();
    }
    printf("TCP_PRESSURE_PASS phases=%u udp_each=32 aborted=2560 companions=%u\n", expiry ? 2 : 1,
           external ? 2 : 0);
    return 0;
}
