// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/socket-splice.c
 * @brief   Socket and pipe splice tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises socket families, queue boundaries, descriptor lifetime, and
 * socket deadlines in both splice directions.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "SOCKET_SPLICE_FAIL line=%d errno=%d %s\n", __LINE__, errno,           \
                    #condition);                                                                   \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void close_pair(int pair[2]) {
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

static long milliseconds(void) {
    struct timespec time;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static socklen_t bind_loopback(int fd, int domain, struct sockaddr_storage* address) {
    socklen_t size;
    if (domain == AF_INET) {
        struct sockaddr_in ipv4 = {.sin_family = AF_INET,
                                   .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        memcpy(address, &ipv4, sizeof(ipv4));
        size = sizeof(ipv4);
    } else {
        struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        memcpy(address, &ipv6, sizeof(ipv6));
        size = sizeof(ipv6);
    }
    CHECK(bind(fd, (struct sockaddr*)address, size) == 0);
    CHECK(getsockname(fd, (struct sockaddr*)address, &size) == 0);
    return size;
}

static void connected_pair(int domain, int type, int pair[2]) {
    if (domain == AF_UNIX) {
        CHECK(socketpair(domain, type, 0, pair) == 0);
        return;
    }
    int endpoint = socket(domain, type, 0);
    pair[0] = socket(domain, type, 0);
    CHECK(endpoint >= 0 && pair[0] >= 0);
    struct sockaddr_storage address = {0};
    socklen_t size = bind_loopback(endpoint, domain, &address);
    if (type == SOCK_STREAM)
        CHECK(listen(endpoint, 1) == 0);
    CHECK(connect(pair[0], (struct sockaddr*)&address, size) == 0);
    if (type == SOCK_STREAM) {
        pair[1] = accept(endpoint, NULL, NULL);
        CHECK(pair[1] >= 0 && close(endpoint) == 0);
    } else {
        pair[1] = endpoint;
        CHECK(getsockname(pair[0], (struct sockaddr*)&address, &size) == 0);
        CHECK(connect(pair[1], (struct sockaddr*)&address, size) == 0);
    }
}

static void transport(int domain, int type, const char* name, int split_datagram) {
    int pair[2], ends[2];
    connected_pair(domain, type, pair);
    CHECK(pipe2(ends, O_DIRECT | O_NONBLOCK) == 0);
    int sender = pair[1], receiver = pair[0];
    int unix_stream = domain == AF_UNIX && type == SOCK_STREAM;
    struct timeval timeout =
        unix_stream ? (struct timeval){.tv_sec = 3} : (struct timeval){.tv_usec = 90000};
    CHECK(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    long start = milliseconds();
    CHECK(splice(receiver, NULL, ends[1], NULL, 2, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
    long elapsed = milliseconds() - start;
    CHECK(unix_stream ? elapsed < 1500 : elapsed >= 50 && elapsed < 2000);
    CHECK(send(sender, "abcd", 4, 0) == 4);
    loff_t offset = 0;
    CHECK(splice(receiver, &offset, ends[1], NULL, 2, SPLICE_F_NONBLOCK) == -1 && errno == EINVAL);
    CHECK(splice(receiver, NULL, ends[1], NULL, 2, SPLICE_F_NONBLOCK) == 2);
    char bytes[16];
    CHECK(read(ends[0], bytes, sizeof(bytes)) == 2 && !memcmp(bytes, "ab", 2));
    if (type == SOCK_STREAM)
        CHECK(recv(receiver, bytes, 2, MSG_WAITALL) == 2 && !memcmp(bytes, "cd", 2));
    else
        CHECK(recv(receiver, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN);

    CHECK(write(ends[1], "ef", 2) == 2 && write(ends[1], "gh", 2) == 2);
    CHECK(splice(ends[0], NULL, receiver, &offset, 3, SPLICE_F_NONBLOCK) == -1 && errno == EINVAL);
    CHECK(splice(ends[0], NULL, receiver, NULL, 3, SPLICE_F_NONBLOCK) == 3);
    if (split_datagram) {
        CHECK(recv(sender, bytes, sizeof(bytes), MSG_DONTWAIT) == 2 && !memcmp(bytes, "ef", 2));
        CHECK(recv(sender, bytes, sizeof(bytes), MSG_DONTWAIT) == 1 && *bytes == 'g');
    } else {
        size_t length = type == SOCK_STREAM ? 3 : sizeof(bytes);
        CHECK(recv(sender, bytes, length, type == SOCK_STREAM ? MSG_WAITALL : 0) == 3 &&
              !memcmp(bytes, "efg", 3));
    }
    CHECK(read(ends[0], bytes, sizeof(bytes)) == 1 && *bytes == 'h');
    CHECK(recv(sender, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    if (type == SOCK_STREAM) {
        CHECK(shutdown(sender, SHUT_WR) == 0);
        CHECK(splice(receiver, NULL, ends[1], NULL, 2, 0) == 0);
    }
    close_pair(ends);
    close_pair(pair);
    if (type == SOCK_DGRAM)
        printf("SOCKET_SPLICE_DATAGRAM %s=%s\n", name, split_datagram ? "split" : "batched");
    printf("SOCKET_SPLICE_CASE %s\n", name);
}

static void large_datagram(void) {
    int pair[2], ends[2];
    connected_pair(AF_UNIX, SOCK_DGRAM, pair);
    CHECK(pipe2(ends, O_NONBLOCK) == 0);
    CHECK(fcntl(ends[1], F_SETPIPE_SZ, 131072) == 131072);
    char input[90000], output[90000];
    for (size_t i = 0; i < sizeof(input); ++i)
        input[i] = 'a' + (i / 4096 + i) % 26;
    CHECK(send(pair[1], input, sizeof(input), MSG_DONTWAIT) == sizeof(input));
    CHECK(splice(pair[0], NULL, ends[1], NULL, sizeof(input), SPLICE_F_NONBLOCK) == sizeof(input));
    CHECK(read(ends[0], output, sizeof(output)) == sizeof(output));
    CHECK(!memcmp(input, output, sizeof(input)));
    CHECK(recv(pair[0], output, sizeof(output), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    close_pair(ends);
    close_pair(pair);
    puts("SOCKET_SPLICE_CASE large-datagram");
}

static void unix_rights(void) {
    int pair[2], payload[2], rights[2];
    connected_pair(AF_UNIX, SOCK_STREAM, pair);
    CHECK(pipe(payload) == 0 && pipe2(rights, O_NONBLOCK) == 0);

    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};

    char message[] = "rights";
    struct iovec vector = {.iov_base = message, .iov_len = 6};
    struct msghdr header = {.msg_iov = &vector,
                            .msg_iovlen = 1,
                            .msg_control = control.bytes,
                            .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr* record = CMSG_FIRSTHDR(&header);
    record->cmsg_level = SOL_SOCKET;
    record->cmsg_type = SCM_RIGHTS;
    record->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(record), &rights[1], sizeof(int));
    CHECK(sendmsg(pair[1], &header, 0) == 6 && close(rights[1]) == 0);
    CHECK(send(pair[1], "tail", 4, 0) == 4);
    char bytes[8];
    CHECK(read(rights[0], bytes, 1) == -1 && errno == EAGAIN);
    CHECK(splice(pair[0], NULL, payload[1], NULL, 16, SPLICE_F_NONBLOCK) == 6);
    CHECK(read(payload[0], bytes, sizeof(bytes)) == 6 && !memcmp(bytes, message, 6));
    CHECK(read(rights[0], bytes, 1) == 0 && close(rights[0]) == 0);
    vector.iov_base = bytes;
    vector.iov_len = sizeof(bytes);
    CHECK(recvmsg(pair[0], &header, MSG_DONTWAIT) == 4 && !memcmp(bytes, "tail", 4));
    CHECK(header.msg_controllen == 0);
    close_pair(payload);
    close_pair(pair);
    puts("SOCKET_SPLICE_CASE unix-rights");
}

struct transfer {
    int input, output, ready, done;
};

static void* splice_one(void* data) {
    struct transfer* call = data;
    CHECK(write(call->ready, "r", 1) == 1);
    CHECK(splice(call->input, NULL, call->output, NULL, 1, 0) == 1);
    CHECK(write(call->done, "d", 1) == 1);
    return NULL;
}

static void retained(int sending) {
    int original[2], replacement[2], ends[2], ready[2], done[2];
    connected_pair(AF_UNIX, SOCK_STREAM, original);
    connected_pair(AF_UNIX, SOCK_STREAM, replacement);
    CHECK(pipe(ends) == 0 && pipe(ready) == 0 && pipe(done) == 0);
    if (sending)
        CHECK(fcntl(original[0], F_SETFL, O_NONBLOCK) == 0);
    struct transfer call = {
        .input = sending ? ends[0] : original[0],
        .output = sending ? original[0] : ends[1],
        .ready = ready[1],
        .done = done[1],
    };
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, splice_one, &call) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
    struct pollfd observed = {.fd = done[0], .events = POLLIN};
    CHECK(poll(&observed, 1, 80) == 0);
    CHECK(dup2(replacement[0], original[0]) == original[0]);
    if (sending)
        CHECK(write(ends[1], "z", 1) == 1);
    else
        CHECK(send(original[1], "z", 1, 0) == 1);
    CHECK(poll(&observed, 1, 3000) == 1 && read(done[0], &byte, 1) == 1 && byte == 'd');
    CHECK(pthread_join(worker, NULL) == 0);
    if (sending) {
        CHECK(recv(original[1], &byte, 1, MSG_DONTWAIT) == 1 && byte == 'z');
        CHECK(recv(replacement[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    } else {
        CHECK(read(ends[0], &byte, 1) == 1 && byte == 'z');
    }
    close_pair(original);
    close_pair(replacement);
    close_pair(ends);
    close_pair(ready);
    close_pair(done);
    puts(sending ? "SOCKET_SPLICE_CASE retained-output" : "SOCKET_SPLICE_CASE retained-input");
}

static void backpressure(void) {
    int pair[2], ends[2];
    connected_pair(AF_UNIX, SOCK_STREAM, pair);
    CHECK(pipe(ends) == 0);
    CHECK(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    char input[4096], output[4096];
    for (size_t i = 0; i < sizeof(input); ++i)
        input[i] = 'a' + i % 26;
    size_t queued = 0, pending = 0;
    for (;;) {
        if (!pending) {
            CHECK(write(ends[1], input, sizeof(input)) == sizeof(input));
            pending = sizeof(input);
        }
        ssize_t count = splice(ends[0], NULL, pair[0], NULL, pending, 0);
        if (count == -1) {
            CHECK(errno == EAGAIN);
            break;
        }
        CHECK(count > 0 && (size_t)count <= pending && queued < 8 * 1024 * 1024);
        queued += count;
        pending -= count;
    }
    CHECK(queued > 0 && pending > 0);
    CHECK(fcntl(pair[0], F_SETFL, 0) == 0);
    struct timeval timeout = {.tv_usec = 90000};
    CHECK(setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    long start = milliseconds();
    CHECK(splice(ends[0], NULL, pair[0], NULL, pending, SPLICE_F_NONBLOCK) == -1 &&
          errno == EAGAIN);
    long elapsed = milliseconds() - start;
    CHECK(elapsed >= 50 && elapsed < 2000);
    while (queued) {
        ssize_t count = recv(pair[1], output, sizeof(output), MSG_DONTWAIT);
        CHECK(count > 0 && (size_t)count <= queued);
        queued -= count;
    }
    CHECK(splice(ends[0], NULL, pair[0], NULL, pending, 0) == (ssize_t)pending);
    CHECK(recv(pair[1], output, pending, MSG_WAITALL) == (ssize_t)pending);
    CHECK(!memcmp(output, input + sizeof(input) - pending, pending));
    close_pair(pair);
    close_pair(ends);
    puts("SOCKET_SPLICE_CASE send-backpressure");
}

static void splice_bytes(int socket, const char* bytes, unsigned flags) {
    const size_t length = strlen(bytes);
    int ends[2];
    CHECK(pipe(ends) == 0 && write(ends[1], bytes, length) == (ssize_t)length);
    CHECK(splice(ends[0], NULL, socket, NULL, length, flags) == (ssize_t)length);
    close_pair(ends);
}

static void expect_packet(int socket, const char* expected) {
    struct pollfd watch = {.fd = socket, .events = POLLIN};
    CHECK(poll(&watch, 1, expected ? 2000 : 40) == (expected != NULL));
    if (expected) {
        char bytes[64];
        size_t length = strlen(expected);
        CHECK(recv(socket, bytes, sizeof(bytes), MSG_DONTWAIT) == (ssize_t)length &&
              !memcmp(bytes, expected, length));
    }
}

static void expect_hops(int receiver, int level, int kind, int hops) {
    char bytes[4];

    union {
        struct cmsghdr aligned;
        char data[CMSG_SPACE(sizeof(int))];
    } control;
    struct iovec slice = {.iov_base = bytes, .iov_len = sizeof(bytes)};
    struct msghdr packet = {.msg_iov = &slice,
                            .msg_iovlen = 1,
                            .msg_control = control.data,
                            .msg_controllen = sizeof(control.data)};
    struct pollfd watch = {.fd = receiver, .events = POLLIN};
    CHECK(poll(&watch, 1, 2000) == 1);
    CHECK(recvmsg(receiver, &packet, MSG_DONTWAIT) == 4 && !memcmp(bytes, "abcd", 4));
    struct cmsghdr* item = CMSG_FIRSTHDR(&packet);
    CHECK(item && item->cmsg_level == level && item->cmsg_type == kind &&
          item->cmsg_len == CMSG_LEN(sizeof(int)));
    int received;
    memcpy(&received, CMSG_DATA(item), sizeof(received));
    CHECK(received == hops);
}

static void udp_hops(int sender, int receiver, int domain) {
    int protocol = domain == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int send_hops = domain == AF_INET ? IP_TTL : IPV6_UNICAST_HOPS;
    int receive_hops = domain == AF_INET ? IP_RECVTTL : IPV6_RECVHOPLIMIT;
    int header = domain == AF_INET ? IP_TTL : IPV6_HOPLIMIT;
    int enabled = 1, hops = 37;
    CHECK(setsockopt(receiver, protocol, receive_hops, &enabled, sizeof(enabled)) == 0);
    CHECK(setsockopt(sender, protocol, send_hops, &hops, sizeof(hops)) == 0);
    splice_bytes(sender, "ab", SPLICE_F_MORE);
    hops = 54;
    CHECK(setsockopt(sender, protocol, send_hops, &hops, sizeof(hops)) == 0);
    CHECK(send(sender, "cd", 2, 0) == 2);
    expect_hops(receiver, protocol, header, domain == AF_INET ? 54 : 37);

    union {
        struct cmsghdr aligned;
        char data[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct iovec slice = {.iov_base = (void*)"ab", .iov_len = 2};
    struct msghdr message = {.msg_iov = &slice,
                             .msg_iovlen = 1,
                             .msg_control = control.data,
                             .msg_controllen = sizeof(control.data)};
    struct cmsghdr* item = CMSG_FIRSTHDR(&message);
    item->cmsg_level = protocol;
    item->cmsg_type = header;
    item->cmsg_len = CMSG_LEN(sizeof(int));
    hops = 37;
    memcpy(CMSG_DATA(item), &hops, sizeof(hops));
    CHECK(sendmsg(sender, &message, MSG_MORE) == 2);
    CHECK(send(sender, "cd", 2, 0) == 2);
    expect_hops(receiver, protocol, header, 37);
}

static void udp_more(int domain, const char* name, int native, int legacy_ipv6) {
    struct sockaddr_storage first = {0}, second = {0};
    int receivers[] = {socket(domain, SOCK_DGRAM, 0), socket(domain, SOCK_DGRAM, 0)};
    int sender = socket(domain, SOCK_DGRAM, 0);
    CHECK(receivers[0] >= 0 && receivers[1] >= 0 && sender >= 0);
    socklen_t first_size = bind_loopback(receivers[0], domain, &first);
    socklen_t second_size = bind_loopback(receivers[1], domain, &second);
    CHECK(connect(sender, (struct sockaddr*)&first, first_size) == 0);
    splice_bytes(sender, "ab", SPLICE_F_MORE);
    expect_packet(receivers[0], NULL);
    splice_bytes(sender, "cd", 0);
    expect_packet(receivers[0], "abcd");

    splice_bytes(sender, "ab", SPLICE_F_MORE);
    int alias = dup(sender);
    CHECK(alias >= 0 && send(alias, "cd", 2, 0) == 2 && close(alias) == 0);
    expect_packet(receivers[0], "abcd");
    struct iovec slice = {.iov_base = (void*)"ab", .iov_len = 2};
    struct msghdr message = {.msg_iov = &slice, .msg_iovlen = 1};
    CHECK(sendmsg(sender, &message, MSG_MORE) == 2);
    splice_bytes(sender, "", 0);
    expect_packet(receivers[0], NULL);
    CHECK(send(sender, "", 0, 0) == 0);
    expect_packet(receivers[0], "ab");

    udp_hops(sender, receivers[0], domain);

    splice_bytes(sender, "ab", SPLICE_F_MORE);
    CHECK(sendto(sender, "cd", 2, 0, (struct sockaddr*)&second, second_size) == 2);
    expect_packet(receivers[0], "abcd");
    expect_packet(receivers[1], NULL);

    splice_bytes(sender, "ab", SPLICE_F_MORE);
    CHECK(connect(sender, (struct sockaddr*)&second, second_size) == 0);
    CHECK(send(sender, "cd", 2, 0) == 2);
    expect_packet(receivers[legacy_ipv6 ? 0 : 1], "abcd");
    expect_packet(receivers[legacy_ipv6 ? 1 : 0], NULL);

    int ends[2];
    CHECK(pipe2(ends, O_NONBLOCK) == 0);
    CHECK(fcntl(ends[1], F_SETPIPE_SZ, 131072) == 131072);
    static char sequence[] __attribute__((aligned(4096))) = "ABCDEFGHIJKLMNOPQ";
    struct iovec slots[sizeof(sequence) - 1];
    for (size_t i = 0; i < sizeof(sequence) - 1; ++i)
        slots[i] = (struct iovec){.iov_base = sequence + i, .iov_len = 1};
    CHECK(vmsplice(ends[1], slots, sizeof(sequence) - 1, 0) == sizeof(sequence) - 1);
    CHECK(fcntl(ends[1], F_SETPIPE_SZ, 65536) == -1 && errno == EBUSY);
    CHECK(splice(ends[0], NULL, sender, NULL, sizeof(sequence) - 1, SPLICE_F_NONBLOCK) ==
          sizeof(sequence) - 1);
    const char* batch = "coalesced";
    if (legacy_ipv6) {
        for (size_t i = 0; i < sizeof(sequence) - 1; ++i) {
            char packet[] = {sequence[i], 0};
            expect_packet(receivers[1], packet);
        }
        batch = "split";
    } else {
        struct pollfd watch = {.fd = receivers[1], .events = POLLIN};
        int ready = poll(&watch, 1, 2000);
        CHECK(ready == 1 || (native && ready == 0));
        if (ready)
            expect_packet(receivers[1], sequence);
        else {
            CHECK(send(sender, "Z", 1, 0) == 1);
            expect_packet(receivers[1], "Z");
            batch = "dropped";
        }
    }
    printf("SOCKET_SPLICE_UDP_BATCH ipv%d=%s\n", domain == AF_INET ? 4 : 6, batch);
    expect_packet(receivers[1], NULL);
    close_pair(ends);

    char full[65000] = {0};
    CHECK(send(sender, full, sizeof(full), MSG_MORE) == sizeof(full));
    CHECK(pipe(ends) == 0 && write(ends[1], full, 1000) == 1000);
    CHECK(splice(ends[0], NULL, sender, NULL, 1000, 0) == -1 && errno == EMSGSIZE);
    memset(full, 1, 1000);
    CHECK(read(ends[0], full, 1000) == 1000 && full[0] == 0 && full[999] == 0);
    close_pair(ends);
    CHECK(send(sender, "z", 1, 0) == 1);
    expect_packet(receivers[1], "z");
    int cork = -1;
    socklen_t size = sizeof(cork);
    CHECK(getsockopt(sender, IPPROTO_UDP, UDP_CORK, &cork, &size) == 0 && cork == 0);
    cork = -1;
    CHECK(setsockopt(sender, IPPROTO_UDP, UDP_CORK, &cork, sizeof(cork)) == 0);
    CHECK(getsockopt(sender, IPPROTO_UDP, UDP_CORK, &cork, &size) == 0 && cork == 1);
    CHECK(send(sender, "ab", 2, 0) == 2);
    splice_bytes(sender, "cd", 0);
    expect_packet(receivers[1], NULL);
    cork = 0;
    CHECK(setsockopt(sender, IPPROTO_UDP, UDP_CORK, &cork, sizeof(cork)) == 0);
    expect_packet(receivers[1], "abcd");
    splice_bytes(sender, "ab", SPLICE_F_MORE);
    CHECK(setsockopt(sender, IPPROTO_UDP, UDP_CORK, &cork, sizeof(cork)) == 0);
    expect_packet(receivers[1], "ab");
    splice_bytes(sender, "ab", SPLICE_F_MORE);
    CHECK(close(sender) == 0);
    expect_packet(receivers[1], NULL);
    close_pair(receivers);
    printf("SOCKET_SPLICE_CASE %s\n", name);
}

static void send_record(int socket, const void* bytes, size_t count) {
    int ends[2];
    CHECK(pipe(ends) == 0 && write(ends[1], bytes, count) == (ssize_t)count);
    loff_t offset = 0;
    CHECK(splice(ends[0], NULL, socket, &offset, count, 0) == -1 && errno == EINVAL);
    CHECK(splice(ends[0], NULL, socket, NULL, count, 0) == (ssize_t)count);
    close_pair(ends);
}

static size_t receive_record(int socket, void* bytes, size_t capacity) {
    int ends[2];
    CHECK(pipe(ends) == 0);
    struct pollfd watch = {.fd = socket, .events = POLLIN};
    CHECK(poll(&watch, 1, 2000) == 1);
    loff_t offset = 0;
    CHECK(splice(socket, &offset, ends[1], NULL, capacity, SPLICE_F_NONBLOCK) == -1 &&
          errno == EINVAL);
    ssize_t count = splice(socket, NULL, ends[1], NULL, capacity, SPLICE_F_NONBLOCK);
    CHECK(count > 0 && read(ends[0], bytes, capacity) == count);
    close_pair(ends);
    return count;
}

static void route_netlink(void) {
    int socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    CHECK(socket_fd >= 0);
    const struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    CHECK(connect(socket_fd, (const struct sockaddr*)&kernel, sizeof(kernel)) == 0);
    struct sockaddr_nl local;
    socklen_t size = sizeof(local);
    CHECK(getsockname(socket_fd, (struct sockaddr*)&local, &size) == 0 && size == sizeof(local));

    struct {
        struct nlmsghdr header;
        struct ifinfomsg link;
    } request = {.header = {.nlmsg_len = sizeof(request),
                            .nlmsg_type = RTM_GETLINK,
                            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                            .nlmsg_seq = 7654}};

    send_record(socket_fd, &request, sizeof(request));

    union {
        struct nlmsghdr align;
        char bytes[16384];
    } reply;

    int loopback = 0, done = 0;
    for (unsigned i = 0; i < 16 && !done; ++i) {
        int remaining = receive_record(socket_fd, reply.bytes, sizeof(reply.bytes));
        for (struct nlmsghdr* message = &reply.align; NLMSG_OK(message, remaining);
             message = NLMSG_NEXT(message, remaining)) {
            CHECK(!done && message->nlmsg_seq == request.header.nlmsg_seq &&
                  message->nlmsg_pid == local.nl_pid && (message->nlmsg_flags & NLM_F_MULTI));
            if (message->nlmsg_type == NLMSG_DONE) {
                done = 1;
                continue;
            }
            CHECK(message->nlmsg_type == RTM_NEWLINK &&
                  message->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg)));
            const struct ifinfomsg* link = NLMSG_DATA(message);
            int attributes = IFLA_PAYLOAD(message);
            for (struct rtattr* attr = IFLA_RTA(link); RTA_OK(attr, attributes);
                 attr = RTA_NEXT(attr, attributes)) {
                if (attr->rta_type == IFLA_IFNAME && RTA_PAYLOAD(attr) == 3 &&
                    !memcmp(RTA_DATA(attr), "lo", 3)) {
                    CHECK(link->ifi_flags & IFF_LOOPBACK);
                    loopback = 1;
                }
            }
            CHECK(attributes == 0);
        }
        CHECK(remaining == 0);
    }
    CHECK(loopback && done);
    int ends[2];
    CHECK(pipe(ends) == 0);
    CHECK(splice(socket_fd, NULL, ends[1], NULL, 1, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
    close_pair(ends);
    CHECK(close(socket_fd) == 0);
    puts("SOCKET_SPLICE_CASE route-netlink");
}

static void packet_link(int sender, int receiver, const char* name, unsigned lane, int native) {
    int control = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(control >= 0);
    struct ifreq query = {0};
    memcpy(query.ifr_name, name, strlen(name) + 1);
    CHECK(ioctl(control, SIOCGIFINDEX, &query) == 0 && query.ifr_ifindex > 0);
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET, .sll_protocol = htons(0x88b5), .sll_ifindex = query.ifr_ifindex};
    CHECK(ioctl(control, SIOCGIFFLAGS, &query) == 0);
    if (!(query.ifr_flags & IFF_UP)) {
        query.ifr_flags |= IFF_UP;
        CHECK(ioctl(control, SIOCSIFFLAGS, &query) == 0);
    }
    CHECK(ioctl(control, SIOCGIFHWADDR, &query) == 0 && close(control) == 0);
    CHECK(bind(sender, (const struct sockaddr*)&address, sizeof(address)) == 0);
    CHECK(bind(receiver, (const struct sockaddr*)&address, sizeof(address)) == 0);

    unsigned char outgoing[64] = {0}, incoming[64], expected[64];
    const unsigned char peer[] = {2, 0x9a, 0x58, 0x4d, 0x64, lane};
    if (!native)
        memcpy(outgoing, peer, sizeof(peer));
    memcpy(outgoing + 6, query.ifr_hwaddr.sa_data, 6);
    outgoing[12] = 0x88;
    outgoing[13] = 0xb5;
    for (unsigned sequence = 0; sequence < 2; ++sequence) {
        for (size_t i = 14; i < sizeof(outgoing); ++i)
            outgoing[i] = 0x40 + lane + sequence * 7 + i - 14;
        send_record(sender, outgoing, sizeof(outgoing));
        memcpy(expected, outgoing, sizeof(expected));
        if (!native) {
            memcpy(expected, outgoing + 6, 6);
            memcpy(expected + 6, outgoing, 6);
            for (size_t i = 14; i < sizeof(expected); ++i)
                expected[i] ^= 0x80;
        }
        size_t count = sequence ? sizeof(incoming) : sizeof(incoming) - 1;
        CHECK(receive_record(receiver, incoming, count) == count &&
              !memcmp(incoming, expected, count));
    }
}

static void raw_packets(int native) {
    int protocol = htons(0x88b5);
    int pair[2] = {socket(AF_PACKET, SOCK_RAW, protocol), -1};
    if (getuid()) {
        CHECK(pair[0] == -1 && errno == EPERM);
    } else {
        pair[1] = socket(AF_PACKET, SOCK_RAW, protocol);
        CHECK(pair[0] >= 0 && pair[1] >= 0);
        packet_link(pair[0], pair[1], native ? "lo" : "eth0", 0, native);
        if (!native)
            packet_link(pair[0], pair[1], "eth1", 1, native);
        close_pair(pair);
    }
    puts("SOCKET_SPLICE_CASE raw-packets");
}

int main(int argc, char** argv) {
    int native = 0, legacy_datagrams = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--ordinary"))
            CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        else if (!strcmp(argv[i], "--native"))
            native = 1;
        else {
            CHECK(!strcmp(argv[i], "--legacy-datagrams"));
            legacy_datagrams = 1;
        }
    }
    transport(AF_UNIX, SOCK_STREAM, "unix-stream", 0);
    transport(AF_UNIX, SOCK_DGRAM, "unix-datagram", legacy_datagrams);
    large_datagram();
    transport(AF_INET, SOCK_STREAM, "tcp4", 0);
    transport(AF_INET6, SOCK_STREAM, "tcp6", 0);
    transport(AF_INET, SOCK_DGRAM, "udp4", 0);
    transport(AF_INET6, SOCK_DGRAM, "udp6", legacy_datagrams);
    unix_rights();
    retained(0);
    retained(1);
    backpressure();
    udp_more(AF_INET, "udp4-more", native, 0);
    udp_more(AF_INET6, "udp6-more", native, legacy_datagrams);
    route_netlink();
    raw_packets(native);
    printf("SOCKET_SPLICE_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}
