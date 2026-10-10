// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "TCP_TEST_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,     \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void creation(void) {
    const int flags[] = {0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC};
    const int protocols[] = {0, IPPROTO_TCP};
    unsigned count = 0;
    for (unsigned p = 0; p < sizeof(protocols) / sizeof(protocols[0]); p++)
        for (unsigned f = 0; f < sizeof(flags) / sizeof(flags[0]); f++) {
            int fd = socket(AF_INET, SOCK_STREAM | flags[f], protocols[p]);
            CHECK(fd >= 0);
            int value = 0;
            socklen_t length = sizeof(value);
            CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &length) == 0 &&
                  value == SOCK_STREAM);
            length = sizeof(value);
            CHECK(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &value, &length) == 0 &&
                  value == IPPROTO_TCP);
            CHECK(!!(fcntl(fd, F_GETFL) & O_NONBLOCK) == !!(flags[f] & SOCK_NONBLOCK));
            CHECK(!!(fcntl(fd, F_GETFD) & FD_CLOEXEC) == !!(flags[f] & SOCK_CLOEXEC));
            struct sockaddr_in address;
            length = sizeof(address);
            CHECK(getsockname(fd, (struct sockaddr*)&address, &length) == 0);
            CHECK(length == sizeof(address) && address.sin_family == AF_INET && !address.sin_port &&
                  !address.sin_addr.s_addr);
            CHECK(close(fd) == 0);
            count++;
        }
    errno = 0;
    CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == -1 && errno == EPROTONOSUPPORT);
    errno = 0;
    CHECK(socket(AF_INET, SOCK_STREAM | 0x10000, 0) == -1 && errno == EINVAL);
    printf("TCP_CREATE_PASS variants=%u flags names protocols errors\n", count);
}

static void timeouts(int fd) {
    struct timeval timeout = {5, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
}

static void send_all(int fd, const uint8_t* data, size_t length) {
    while (length) {
        ssize_t count = send(fd, data, length, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count > 0 && (size_t)count <= length);
        data += count;
        length -= count;
    }
}

static uint8_t pattern(size_t position) {
    return (uint8_t)((position * 37) ^ (position >> 8));
}

static uint64_t hash_byte(uint64_t hash, uint8_t value) {
    return (hash ^ value) * UINT64_C(1099511628211);
}

enum { payload_bytes = 262144 };

static void client(int listener, const struct sockaddr_in* destination) {
    CHECK(close(listener) == 0);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    timeouts(fd);
    CHECK(connect(fd, (const struct sockaddr*)destination, sizeof(*destination)) == 0);
    struct sockaddr_in peer, local;
    socklen_t length = sizeof(peer);
    CHECK(getpeername(fd, (struct sockaddr*)&peer, &length) == 0 &&
          peer.sin_port == destination->sin_port);
    length = sizeof(local);
    CHECK(getsockname(fd, (struct sockaddr*)&local, &length) == 0 && local.sin_port &&
          local.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    uint8_t bytes[4096];
    uint64_t expected = UINT64_C(14695981039346656037);
    for (size_t position = 0; position < payload_bytes; position += sizeof(bytes)) {
        for (size_t at = 0; at < sizeof(bytes); at++) {
            bytes[at] = pattern(position + at);
            expected = hash_byte(expected, bytes[at]);
        }
        send_all(fd, bytes, sizeof(bytes));
    }
    CHECK(shutdown(fd, SHUT_WR) == 0);
    uint8_t digest[8];
    size_t received = 0;
    while (received < sizeof(digest)) {
        ssize_t count = recv(fd, digest + received, sizeof(digest) - received, 0);
        CHECK(count > 0);
        received += count;
    }
    uint64_t actual = 0;
    for (unsigned at = 0; at < sizeof(digest); at++)
        actual = actual << 8 | digest[at];
    CHECK(actual == expected && recv(fd, bytes, 1, 0) == 0);
    CHECK(close(fd) == 0);
    puts("TCP_CLIENT_PASS connect names partial_send shutdown reply eof");
    fflush(stdout);
    _exit(0);
}

static void loopback(void) {
    int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(listener >= 0);
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&destination, sizeof(destination)) == 0);
    CHECK(listen(listener, 8) == 0);
    socklen_t length = sizeof(destination);
    CHECK(getsockname(listener, (struct sockaddr*)&destination, &length) == 0 &&
          destination.sin_port);
    int value = 0;
    length = sizeof(value);
    CHECK(getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) == 0 && value == 1);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid)
        client(listener, &destination);
    struct sockaddr_in peer;
    length = sizeof(peer);
    int fd = accept4(listener, (struct sockaddr*)&peer, &length, SOCK_CLOEXEC);
    CHECK(fd >= 0 && peer.sin_family == AF_INET && peer.sin_port &&
          peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
    CHECK(!(fcntl(fd, F_GETFL) & O_NONBLOCK));
    timeouts(fd);
    CHECK(close(listener) == 0);
    uint8_t bytes[8192];
    size_t received = 0;
    uint64_t digest = UINT64_C(14695981039346656037);
    for (;;) {
        ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count >= 0);
        if (!count)
            break;
        for (ssize_t at = 0; at < count; at++) {
            CHECK(received < payload_bytes && bytes[at] == pattern(received));
            received++;
            digest = hash_byte(digest, bytes[at]);
        }
    }
    CHECK(received == payload_bytes);
    uint8_t response[8];
    for (unsigned at = 0; at < sizeof(response); at++)
        response[at] = digest >> (56 - at * 8);
    send_all(fd, response, sizeof(response));
    CHECK(shutdown(fd, SHUT_WR) == 0 && close(fd) == 0);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    printf("TCP_LOOPBACK_PASS bytes=%u bind listen accept4 fork exact_bytes half_close\n",
           payload_bytes);
}

static void readable(int fd) {
    struct pollfd item = {.fd = fd, .events = POLLIN};
    CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLIN) && !(item.revents & POLLERR));
}

static void pair_sockets(int pair[2]) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    socklen_t size = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &size) == 0);
    errno = 0;
    CHECK(accept4(listener, NULL, NULL, 0) == -1 && errno == EAGAIN);
    pair[0] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(pair[0] >= 0);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0;
    CHECK(connect(pair[0], (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    readable(listener);
    pair[1] = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(pair[1] >= 0 && (fcntl(pair[1], F_GETFL) & O_NONBLOCK) &&
          (fcntl(pair[1], F_GETFD) & FD_CLOEXEC));
    struct pollfd item = {.fd = pair[0], .events = POLLOUT};
    CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLOUT) && !(item.revents & POLLERR));
    int error = -1;
    size = sizeof(error);
    CHECK(getsockopt(pair[0], SOL_SOCKET, SO_ERROR, &error, &size) == 0 && !error);
    CHECK(close(listener) == 0);
}

static void options(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    const int names[] = {TCP_NODELAY, TCP_USER_TIMEOUT};
    for (unsigned at = 0; at < sizeof(names) / sizeof(names[0]); at++) {
        int value = -1;
        socklen_t size = sizeof(value);
        CHECK(getsockopt(fd, IPPROTO_TCP, names[at], &value, &size) == 0 && value == 0);
        value = names[at] == TCP_NODELAY ? 1 : 2000;
        CHECK(setsockopt(fd, IPPROTO_TCP, names[at], &value, sizeof(value)) == 0);
        int actual = 0;
        size = sizeof(actual);
        CHECK(getsockopt(fd, IPPROTO_TCP, names[at], &actual, &size) == 0 && actual == value);
    }
    int value = -1;
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, sizeof(value)) == -1 &&
          errno == EINVAL);
    value = 87;
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &value, sizeof(value)) == -1 && errno == EINVAL);
    value = 32768;
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &value, sizeof(value)) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(setsockopt(fd, IPPROTO_TCP, 9999, &value, sizeof(value)) == -1 && errno == ENOPROTOOPT);
    CHECK(close(fd) == 0);
    puts("TCP_OPTIONS_PASS nodelay user_timeout maxseg invalid_bounds");
}

static void bindings(void) {
    int first = socket(AF_INET, SOCK_STREAM, 0);
    int second = socket(AF_INET, SOCK_STREAM, 0);
    int datagram = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(first >= 0 && second >= 0 && datagram >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET};
    socklen_t size = sizeof(local);
    errno = 0;
    CHECK(getpeername(first, (struct sockaddr*)&local, &size) == -1 && errno == ENOTCONN);
    CHECK(bind(first, (struct sockaddr*)&local, sizeof(local)) == 0);
    size = sizeof(local);
    CHECK(getsockname(first, (struct sockaddr*)&local, &size) == 0 && local.sin_port &&
          !local.sin_addr.s_addr);
    CHECK(bind(datagram, (struct sockaddr*)&local, sizeof(local)) == 0);
    errno = 0;
    CHECK(bind(first, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINVAL);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    errno = 0;
    CHECK(bind(second, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EADDRINUSE);
    errno = 0;
    CHECK(accept4(second, NULL, NULL, 0) == -1 && errno == EINVAL);
    CHECK(close(first) == 0 && close(second) == 0 && close(datagram) == 0);
    puts("TCP_BINDINGS_PASS wildcard conflicts independent_udp_names errors");
}

static void vectors(void) {
    int pair[2];
    pair_sockets(pair);

    enum { bytes = 12293 };

    uint8_t sent[bytes], received[bytes];
    for (unsigned at = 0; at < bytes; at++)
        sent[at] = pattern(at);
    errno = 0;
    CHECK(recv(pair[1], received, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    struct iovec output[] = {{sent, 5000}, {sent + 5000, 1}, {sent + 5001, bytes - 5001}};
    struct msghdr message = {.msg_iov = output, .msg_iovlen = 3};
    CHECK(sendmsg(pair[0], &message, MSG_NOSIGNAL) == bytes);
    readable(pair[1]);
    struct sockaddr_in peer;
    struct iovec input[] = {
        {received, 5000}, {received + 5000, 1}, {received + 5001, bytes - 5001}};
    message = (struct msghdr){
        .msg_name = &peer, .msg_namelen = sizeof(peer), .msg_iov = input, .msg_iovlen = 3};
    // The peer has no concurrent writer; repeat peek until the complete payload has arrived.
    ssize_t count;
    do {
        count = recvmsg(pair[1], &message, MSG_PEEK);
        CHECK(count > 0 && count <= bytes && !memcmp(sent, received, count));
    } while (count != bytes);
    CHECK(!message.msg_namelen && !message.msg_controllen && !message.msg_flags);
    int copy = dup(pair[1]);
    CHECK(copy >= 0 && close(pair[1]) == 0);
    CHECK(readv(copy, input, 3) == bytes && !memcmp(sent, received, bytes));
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.u64 = 0x746370};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, copy, &event) == 0);
    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 2000) == 1 && event.data.u64 == 0x746370 &&
          (event.events & EPOLLIN) && (event.events & EPOLLRDHUP));
    CHECK(recv(copy, received, 1, 0) == 0);
    CHECK(close(copy) == 0 && close(pair[0]) == 0 && close(epoll) == 0);
    puts("TCP_VECTORS_PASS nonblocking sendmsg recvmsg peek readv dup poll epoll eof");
}

static void refused(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0);
    socklen_t size = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &size) == 0 && close(listener) == 0);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    int value = -1;
    size = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &size) == 0 && value == 0);
    CHECK(connect(fd, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    struct pollfd item = {.fd = fd, .events = POLLOUT};
    CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLOUT) && (item.revents & POLLERR));
    size = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &size) == 0 && value == ECONNREFUSED);
    size = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &size) == 0 && value == 0);
    CHECK(close(fd) == 0);
    puts("TCP_REFUSED_PASS nonblocking poll so_error clear");
}

static volatile sig_atomic_t interrupted;

static void interruption(int signal) {
    (void)signal;
    interrupted++;
}

static void wait_child(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
}

static void wait_all(void) {
    for (unsigned peek = 0; peek < 2; peek++) {
        int pair[2];
        pair_sockets(pair);
        CHECK(fcntl(pair[1], F_SETFL, fcntl(pair[1], F_GETFL) & ~O_NONBLOCK) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(close(pair[1]) == 0);
            send_all(pair[0], (const uint8_t*)"part", 4);
            CHECK(usleep(30000) == 0);
            send_all(pair[0], (const uint8_t*)"full", 4);
            CHECK(shutdown(pair[0], SHUT_WR) == 0 && close(pair[0]) == 0);
            _exit(0);
        }
        CHECK(close(pair[0]) == 0);
        uint8_t bytes[8];
        CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_WAITALL | (peek ? MSG_PEEK : 0)) == 8 &&
              !memcmp(bytes, "partfull", sizeof(bytes)));
        if (peek)
            CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_WAITALL) == 8 &&
                  !memcmp(bytes, "partfull", 8));
        CHECK(recv(pair[1], bytes, 1, 0) == 0 && close(pair[1]) == 0);
        wait_child(child);
    }
    int pair[2];
    pair_sockets(pair);
    send_all(pair[0], (const uint8_t*)"part", 4);
    readable(pair[1]);
    uint8_t bytes[8];
    CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_WAITALL | MSG_DONTWAIT) == 4 &&
          !memcmp(bytes, "part", 4));
    send_all(pair[0], (const uint8_t*)"time", 4);
    readable(pair[1]);
    struct timeval deadline = {0, 50000};
    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) == 0);
    CHECK(fcntl(pair[1], F_SETFL, fcntl(pair[1], F_GETFL) & ~O_NONBLOCK) == 0);
    CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_WAITALL) == 4 && !memcmp(bytes, "time", 4));
    errno = 0;
    CHECK(recv(pair[1], bytes, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    puts("TCP_WAITALL_PASS delayed_chunks peek nonblocking timeout_partial");
}

static void wait_all_signals(void) {
    struct sigaction previous, action = {.sa_handler = interruption};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, NULL, &previous) == 0);
    for (unsigned restart = 0; restart < 2; restart++) {
        action.sa_flags = restart ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        int pair[2], ready[2];
        pair_sockets(pair);
        CHECK(pipe(ready) == 0);
        CHECK(fcntl(pair[1], F_SETFL, fcntl(pair[1], F_GETFL) & ~O_NONBLOCK) == 0);
        pid_t parent = getpid(), child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(close(pair[1]) == 0 && close(ready[1]) == 0);
            send_all(pair[0], (const uint8_t*)"part", 4);
            uint8_t byte;
            CHECK(read(ready[0], &byte, 1) == 1 && usleep(30000) == 0);
            CHECK(kill(parent, SIGUSR1) == 0 && usleep(30000) == 0);
            send_all(pair[0], (const uint8_t*)"late", 4);
            CHECK(shutdown(pair[0], SHUT_WR) == 0 && close(pair[0]) == 0 && close(ready[0]) == 0);
            _exit(0);
        }
        CHECK(close(pair[0]) == 0 && close(ready[0]) == 0);
        readable(pair[1]);
        uint8_t bytes[8];
        CHECK(recv(pair[1], bytes, 4, MSG_PEEK | MSG_DONTWAIT) == 4);
        interrupted = 0;
        CHECK(write(ready[1], "x", 1) == 1);
        CHECK(recv(pair[1], bytes, sizeof(bytes), MSG_WAITALL) == 4 && !memcmp(bytes, "part", 4));
        CHECK(interrupted == 1);
        CHECK(recv(pair[1], bytes, 4, MSG_WAITALL) == 4 && !memcmp(bytes, "late", 4));
        CHECK(recv(pair[1], bytes, 1, 0) == 0 && close(pair[1]) == 0 && close(ready[1]) == 0);
        wait_child(child);
    }
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    puts("TCP_WAITALL_SIGNALS_PASS partial_bytes sa_restart_on_off remaining_data");
}

struct RetainedRead {
    int fd;
    uint8_t bytes[8];
    struct iovec vectors[2];
    struct msghdr message;
    atomic_int entered, done;
    ssize_t result;
};

static void* retained_reader(void* opaque) {
    struct RetainedRead* operation = opaque;
    atomic_store(&operation->entered, 1);
    operation->result = recvmsg(operation->fd, &operation->message, MSG_WAITALL);
    atomic_store(&operation->done, 1);
    return NULL;
}

static void retained_reads(void) {
    for (unsigned replace = 0; replace < 2; replace++) {
        int original[2], replacement[2];
        pair_sockets(original);
        CHECK(fcntl(original[1], F_SETFL, fcntl(original[1], F_GETFL) & ~O_NONBLOCK) == 0);
        struct RetainedRead operation = {.fd = original[1]};
        operation.vectors[0] = (struct iovec){operation.bytes, 2};
        operation.vectors[1] = (struct iovec){operation.bytes + 2, 6};
        operation.message = (struct msghdr){.msg_iov = operation.vectors, .msg_iovlen = 2};
        pthread_t thread;
        send_all(original[0], (const uint8_t*)"part", 4);
        CHECK(pthread_create(&thread, NULL, retained_reader, &operation) == 0);
        int available = 1;
        unsigned waits = 0;
        while (!atomic_load(&operation.entered) || available) {
            CHECK(!atomic_load(&operation.done) && waits++ < 2000);
            CHECK(ioctl(original[1], FIONREAD, &available) == 0 && usleep(1000) == 0);
        }
        // FIONREAD reaches zero only after this call has consumed the first prefix.
        CHECK(!atomic_load(&operation.done));
        if (replace) {
            pair_sockets(replacement);
            CHECK(dup2(replacement[0], original[1]) == original[1]);
            CHECK(close(replacement[0]) == 0);
            replacement[0] = original[1];
        } else {
            CHECK(close(original[1]) == 0);
            pair_sockets(replacement);
            CHECK(replacement[0] == original[1]);
        }
        uint8_t poison[8];
        memset(poison, '.', sizeof(poison));
        operation.vectors[0] = (struct iovec){poison, 8};
        operation.vectors[1] = (struct iovec){poison, 8};
        operation.message.msg_iovlen = 1;
        send_all(replacement[1], (const uint8_t*)"wrong", 5);
        CHECK(usleep(20000) == 0 && !atomic_load(&operation.done));
        send_all(original[0], (const uint8_t*)"late", 4);
        CHECK(pthread_join(thread, NULL) == 0 && operation.result == 8 &&
              !memcmp(operation.bytes, "partlate", 8) && !memcmp(poison, "........", 8));
        readable(original[0]);
        uint8_t bytes[8];
        CHECK(recv(original[0], bytes, 1, 0) == 0);
        readable(replacement[0]);
        CHECK(recv(replacement[0], bytes, sizeof(bytes), 0) == 5 && !memcmp(bytes, "wrong", 5));
        CHECK(close(original[0]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
    }
    puts("TCP_RETAINED_READ_PASS cases=2 captured_vectors fd_close_reuse dup2 exact_bytes");
}

static void connection_cycles(void) {
    for (unsigned cycle = 0; cycle < 300; cycle++) {
        int pair[2];
        pair_sockets(pair);
        uint8_t byte;
        CHECK(shutdown(pair[0], SHUT_WR) == 0);
        readable(pair[1]);
        CHECK(recv(pair[1], &byte, 1, 0) == 0);
        CHECK(shutdown(pair[1], SHUT_WR) == 0);
        readable(pair[0]);
        CHECK(recv(pair[0], &byte, 1, 0) == 0);
        CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    }
    puts("TCP_RESOURCE_CYCLES_PASS count=300 completed_half_closes pool_reclamation");
}

static void accept_descriptors(void) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0 && original.rlim_cur >= 16);
    limit = original;
    if (limit.rlim_cur > 128) {
        limit.rlim_cur = 128;
        CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0 && client >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    socklen_t length = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &length) == 0);
    struct timeval timeout = {0, 50000};
    CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    int held[128], count = 0, fd;
    while ((fd = dup(listener)) >= 0) {
        CHECK(count < 128);
        held[count++] = fd;
    }
    CHECK(errno == EMFILE && count > 0);
    errno = 0;
    CHECK(accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC) == -1 && errno == EMFILE);
    CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    readable(listener);
    errno = 0;
    CHECK(accept(listener, NULL, NULL) == -1 && errno == EMFILE);
    int expected = held[--count];
    CHECK(close(expected) == 0);
    fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(fd == expected && (fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    send_all(client, (const uint8_t*)"kept", 4);
    readable(fd);
    uint8_t bytes[4];
    CHECK(recv(fd, bytes, sizeof(bytes), 0) == 4 && !memcmp(bytes, "kept", 4));
    CHECK(close(fd) == 0 && close(client) == 0);
    while (count)
        CHECK(close(held[--count]) == 0);
    CHECK(close(listener) == 0);
    if (limit.rlim_cur != original.rlim_cur)
        CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    puts("TCP_ACCEPT_DESCRIPTORS_PASS empty_listener full_table queued_child preserved flags");
}

struct RetainedAccept {
    int listener, result, error;
    atomic_int entered, done;
};

static void* retained_accept(void* opaque) {
    struct RetainedAccept* operation = opaque;
    atomic_store(&operation->entered, 1);
    operation->result = accept4(operation->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    operation->error = errno;
    atomic_store(&operation->done, 1);
    return NULL;
}

static void accept_waiting(struct RetainedAccept* operation, int expected) {
    for (unsigned attempt = 0; attempt < 1000; attempt++) {
        CHECK(!atomic_load(&operation->done));
        if (atomic_load(&operation->entered)) {
            int probe = dup(operation->listener);
            CHECK(probe >= expected && close(probe) == 0);
            if (probe != expected) {
                errno = 0;
                CHECK(fcntl(expected, F_GETFD) == -1 && errno == EBADF);
                return;
            }
        }
        CHECK(usleep(1000) == 0);
    }
    CHECK(!"blocked accept did not reserve its descriptor");
}

static int tcp_listener(struct sockaddr_in* local) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    *local = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr*)local, sizeof(*local)) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof(*local);
    CHECK(getsockname(fd, (struct sockaddr*)local, &length) == 0);
    return fd;
}

static void accept_lifetime(void) {
    for (unsigned replace = 0; replace < 2; replace++) {
        struct sockaddr_in old_address, new_address;
        int listener = tcp_listener(&old_address);
        int old_client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(old_client >= 0);
        int expected = dup(listener);
        CHECK(expected >= 0 && close(expected) == 0);
        struct RetainedAccept operation = {.listener = listener};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
        accept_waiting(&operation, expected);
        int replacement;
        if (replace) {
            replacement = tcp_listener(&new_address);
            CHECK(dup2(replacement, listener) == listener && close(replacement) == 0);
        } else {
            CHECK(close(listener) == 0);
            replacement = tcp_listener(&new_address);
            CHECK(replacement == listener);
        }
        int new_client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(new_client >= 0);
        CHECK(connect(new_client, (struct sockaddr*)&new_address, sizeof(new_address)) == -1 &&
              errno == EINPROGRESS);
        readable(listener);
        CHECK(!atomic_load(&operation.done));
        CHECK(connect(old_client, (struct sockaddr*)&old_address, sizeof(old_address)) == -1 &&
              errno == EINPROGRESS);
        CHECK(pthread_join(thread, NULL) == 0 && operation.result == expected);
        send_all(old_client, (const uint8_t*)"old", 3);
        readable(expected);
        uint8_t bytes[8];
        CHECK(recv(expected, bytes, sizeof(bytes), 0) == 3 && !memcmp(bytes, "old", 3));
        int accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK);
        CHECK(accepted >= 0);
        send_all(new_client, (const uint8_t*)"new", 3);
        readable(accepted);
        CHECK(recv(accepted, bytes, sizeof(bytes), 0) == 3 && !memcmp(bytes, "new", 3));
        CHECK(close(expected) == 0);
        readable(old_client);
        CHECK(recv(old_client, bytes, 1, 0) == 0);
        CHECK(close(accepted) == 0 && close(old_client) == 0 && close(new_client) == 0 &&
              close(listener) == 0);
    }
    puts("TCP_ACCEPT_LIFETIME_PASS cases=2 fd_close_reuse dup2 original_listener independent_child "
         "owner_release");
}

static void accept_signals(void) {
    struct sigaction previous, action = {.sa_handler = interruption};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, NULL, &previous) == 0);
    for (unsigned mode = 0; mode < 3; mode++) {
        action.sa_flags = mode ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        struct sockaddr_in local;
        int listener = tcp_listener(&local);
        int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        CHECK(client >= 0);
        if (mode == 2) {
            struct timeval timeout = {2, 0};
            CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        }
        int expected = dup(listener);
        CHECK(expected >= 0 && close(expected) == 0);
        struct RetainedAccept operation = {.listener = listener};
        pthread_t thread;
        interrupted = 0;
        CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
        accept_waiting(&operation, expected);
        CHECK(pthread_kill(thread, SIGUSR1) == 0);
        for (unsigned attempt = 0; !interrupted; attempt++)
            CHECK(attempt < 1000 && usleep(1000) == 0);
        if (mode == 1) {
            accept_waiting(&operation, expected);
            CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 &&
                  errno == EINPROGRESS);
            CHECK(pthread_join(thread, NULL) == 0 && operation.result == expected &&
                  close(expected) == 0);
        } else {
            CHECK(pthread_join(thread, NULL) == 0 && operation.result == -1 &&
                  operation.error == EINTR);
            CHECK(dup(listener) == expected && close(expected) == 0);
        }
        CHECK(interrupted == 1 && close(client) == 0 && close(listener) == 0);
    }
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    puts("TCP_ACCEPT_SIGNALS_PASS cases=3 restart interrupted finite_timeout slot_release");
}

static void accept_reservation(void) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0 && original.rlim_cur >= 16);
    limit = original;
    if (limit.rlim_cur > 128) {
        limit.rlim_cur = 128;
        CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(listener >= 0 && client >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    socklen_t length = sizeof(local);
    CHECK(getsockname(listener, (struct sockaddr*)&local, &length) == 0);
    int expected = dup(listener);
    CHECK(expected >= 0 && close(expected) == 0);
    struct RetainedAccept operation = {.listener = listener};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
    int held[128], count = 0, fd = -1;
    for (unsigned attempt = 0; attempt < 1000; attempt++) {
        CHECK(!atomic_load(&operation.done));
        if (atomic_load(&operation.entered)) {
            fd = dup(listener);
            CHECK(fd >= expected);
            if (fd != expected)
                break; // Allocation skipped the waiting call's reserved slot.
            CHECK(close(fd) == 0);
        }
        CHECK(usleep(1000) == 0);
    }
    CHECK(fd > expected && !atomic_load(&operation.done));
    held[count++] = fd;
    errno = 0;
    CHECK(fcntl(expected, F_GETFD) == -1 && errno == EBADF);
    errno = 0;
    CHECK(close(expected) == -1 && errno == EBADF);
    errno = 0;
    // musl retries EBUSY in its wrapper; compare the Linux syscall itself here.
    CHECK(syscall(SYS_dup2, listener, expected) == -1 && errno == EBUSY);
    errno = 0;
    CHECK(syscall(SYS_dup3, listener, expected, O_CLOEXEC) == -1 && errno == EBUSY);
    while ((fd = dup(listener)) >= 0) {
        CHECK(count < 128);
        held[count++] = fd;
    }
    CHECK(errno == EMFILE && !atomic_load(&operation.done));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        // A private fork table contains installed files, not another thread's reservation.
        CHECK(dup(listener) == expected);
        _exit(0);
    }
    wait_child(child);
    CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINPROGRESS);
    CHECK(pthread_join(thread, NULL) == 0 && operation.result == expected);
    CHECK((fcntl(expected, F_GETFL) & O_NONBLOCK) && (fcntl(expected, F_GETFD) & FD_CLOEXEC));
    CHECK(close(expected) == 0 && close(client) == 0);
    while (count)
        CHECK(close(held[--count]) == 0);
    struct timeval timeout = {0, 10000};
    CHECK(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    expected = dup(listener);
    CHECK(expected >= 0 && close(expected) == 0);
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        errno = 0;
        CHECK(accept(listener, NULL, NULL) == -1 && errno == EAGAIN);
        CHECK(dup(listener) == expected && close(expected) == 0);
    }
    CHECK(close(listener) == 0);
    if (limit.rlim_cur != original.rlim_cur)
        CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    puts(
        "TCP_ACCEPT_RESERVATION_PASS blocked_slot pressure dup2_busy fork_private timeout_release");
}

static void accept_teardown(const char* executable) {
    for (unsigned fatal = 0; fatal < 2; fatal++) {
        struct sockaddr_in local;
        int listener = tcp_listener(&local);
        CHECK(fcntl(listener, F_SETFD, FD_CLOEXEC) == 0);
        int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        int ready[2];
        CHECK(client >= 0 && pipe2(ready, O_CLOEXEC) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(close(ready[0]) == 0);
            int expected = dup(listener);
            CHECK(expected >= 0 && close(expected) == 0);
            struct RetainedAccept operation = {.listener = listener};
            pthread_t thread;
            CHECK(pthread_create(&thread, NULL, retained_accept, &operation) == 0);
            accept_waiting(&operation, expected);
            CHECK(write(ready[1], "r", 1) == 1);
            if (fatal) {
                for (;;)
                    pause();
            }
            char minimum[16];
            CHECK(snprintf(minimum, sizeof(minimum), "%d", expected) > 0);
            char* arguments[] = {(char*)executable, "--accept-exec-check", minimum, NULL};
            execv(executable, arguments);
            CHECK(!"exec did not replace the accepting thread group");
        }
        CHECK(close(listener) == 0 && close(ready[1]) == 0);
        char marker;
        CHECK(read(ready[0], &marker, 1) == 1 && marker == 'r');
        if (fatal) {
            CHECK(kill(child, SIGKILL) == 0);
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                  WTERMSIG(status) == SIGKILL);
        } else
            wait_child(child);
        CHECK(close(ready[0]) == 0);
        CHECK(connect(client, (struct sockaddr*)&local, sizeof(local)) == -1 &&
              errno == EINPROGRESS);
        struct pollfd item = {.fd = client, .events = POLLOUT};
        CHECK(poll(&item, 1, 2000) == 1 && (item.revents & POLLERR));
        int error = 0;
        socklen_t length = sizeof(error);
        CHECK(getsockopt(client, SOL_SOCKET, SO_ERROR, &error, &length) == 0 &&
              error == ECONNREFUSED && close(client) == 0);
    }
    puts("TCP_ACCEPT_TEARDOWN_PASS cases=2 exec_private_slot fatal_group listener_owner_release");
}

static void limited_pair(int pair[2]) {
    pair_sockets(pair);
    int size = 4096, enabled = 1;
    CHECK(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0);
    CHECK(setsockopt(pair[0], IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) == 0);
    CHECK(fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) & ~O_NONBLOCK) == 0);
}

static uint8_t* send_pattern(size_t size) {
    uint8_t* bytes = malloc(size);
    CHECK(bytes != NULL);
    for (size_t at = 0; at < size; at++)
        bytes[at] = pattern(at);
    return bytes;
}

static size_t receive_pattern(int fd, size_t maximum) {
    uint8_t bytes[4096];
    size_t received = 0;
    for (;;) {
        readable(fd);
        ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        CHECK(count >= 0);
        if (!count)
            return received;
        for (ssize_t at = 0; at < count; at++) {
            CHECK(received < maximum && bytes[at] == pattern(received));
            received++;
        }
    }
}

struct RetainedSend {
    int fd, message;
    struct iovec vectors[2];
    struct msghdr header;
    ssize_t result;
    atomic_int entered, done;
};

static void* retained_sender(void* opaque) {
    struct RetainedSend* operation = opaque;
    atomic_store(&operation->entered, 1);
    operation->result = operation->message
                            ? sendmsg(operation->fd, &operation->header, MSG_NOSIGNAL)
                            : writev(operation->fd, operation->vectors, 2);
    atomic_store(&operation->done, 1);
    return NULL;
}

static void retained_sends(void) {
    const size_t size = 262149;
    for (unsigned replace = 0; replace < 2; replace++) {
        int original[2], replacement[2];
        limited_pair(original);
        uint8_t* bytes = send_pattern(size);
        struct RetainedSend operation = {.fd = original[0], .message = replace};
        operation.vectors[0] = (struct iovec){bytes, 5000};
        operation.vectors[1] = (struct iovec){bytes + 5000, size - 5000};
        operation.header = (struct msghdr){.msg_iov = operation.vectors, .msg_iovlen = 2};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, retained_sender, &operation) == 0);
        int available = 0;
        for (unsigned attempt = 0; !atomic_load(&operation.entered) || !available; attempt++) {
            if (atomic_load(&operation.done))
                fprintf(stderr, "TCP_BLOCKED_SEND_FAIL expected=%zu returned=%zd flags=%x\n", size,
                        operation.result, fcntl(original[0], F_GETFL));
            CHECK(!atomic_load(&operation.done) && attempt < 2000);
            CHECK(ioctl(original[1], FIONREAD, &available) == 0 && usleep(1000) == 0);
        }
        CHECK(usleep(20000) == 0 && !atomic_load(&operation.done));
        int alias = dup(original[0]);
        CHECK(alias >= 0 && fcntl(alias, F_SETFL, fcntl(alias, F_GETFL) | O_NONBLOCK) == 0);
        CHECK(usleep(20000) == 0 && !atomic_load(&operation.done) && close(alias) == 0);
        if (replace) {
            pair_sockets(replacement);
            CHECK(dup2(replacement[0], original[0]) == original[0] && close(replacement[0]) == 0);
            replacement[0] = original[0];
        } else {
            CHECK(close(original[0]) == 0);
            pair_sockets(replacement);
            CHECK(replacement[0] == original[0]);
        }
        uint8_t poison[64];
        memset(poison, '!', sizeof(poison));
        operation.vectors[0] = (struct iovec){poison, sizeof(poison)};
        operation.vectors[1] = (struct iovec){poison, sizeof(poison)};
        operation.header.msg_iovlen = 1;
        CHECK(receive_pattern(original[1], size) == size);
        CHECK(pthread_join(thread, NULL) == 0 && operation.result == (ssize_t)size);
        errno = 0;
        CHECK(recv(replacement[1], poison, sizeof(poison), MSG_DONTWAIT) == -1 && errno == EAGAIN);
        CHECK(close(original[1]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
        free(bytes);
    }
    puts("TCP_RETAINED_SEND_PASS cases=2 blocking_prefix captured_vectors captured_nonblocking "
         "writev sendmsg fd_replacement exact_bytes owner_release");
}

static uint64_t monotonic_ms(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void send_deadlines(void) {
    const size_t size = 262149;
    for (unsigned operation = 0; operation < 3; operation++) {
        int pair[2];
        limited_pair(pair);
        struct timeval timeout = {0, 50000};
        CHECK(setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
        uint8_t* bytes = send_pattern(size);
        struct iovec vectors[2] = {{bytes, 5000}, {bytes + 5000, size - 5000}};
        uint64_t started = monotonic_ms();
        ssize_t count = operation == 0   ? send(pair[0], bytes, size, MSG_NOSIGNAL)
                        : operation == 1 ? write(pair[0], bytes, size)
                                         : writev(pair[0], vectors, 2);
        uint64_t elapsed = monotonic_ms() - started;
        CHECK(count > 0 && (size_t)count < size && elapsed >= 40 && elapsed < 2000);
        memset(bytes, '!', size);
        free(bytes);
        CHECK(close(pair[0]) == 0);
        CHECK(receive_pattern(pair[1], count) == (size_t)count && close(pair[1]) == 0);
    }
    puts("TCP_SEND_DEADLINES_PASS cases=3 send write writev waited partial_bytes owned_queue "
         "exact_eof");
}

static void send_signals(void) {
    const size_t size = 262149;
    struct sigaction previous, action = {.sa_handler = interruption};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, NULL, &previous) == 0);
    for (unsigned restart = 0; restart < 2; restart++) {
        action.sa_flags = restart ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        int pair[2];
        limited_pair(pair);
        uint8_t* bytes = send_pattern(size);
        struct RetainedSend operation = {.fd = pair[0], .message = restart};
        operation.vectors[0] = (struct iovec){bytes, 5000};
        operation.vectors[1] = (struct iovec){bytes + 5000, size - 5000};
        operation.header = (struct msghdr){.msg_iov = operation.vectors, .msg_iovlen = 2};
        pthread_t thread;
        interrupted = 0;
        CHECK(pthread_create(&thread, NULL, retained_sender, &operation) == 0);
        int available = 0;
        for (unsigned attempt = 0; !atomic_load(&operation.entered) || !available; attempt++) {
            CHECK(!atomic_load(&operation.done) && attempt < 2000);
            CHECK(ioctl(pair[1], FIONREAD, &available) == 0 && usleep(1000) == 0);
        }
        CHECK(usleep(20000) == 0 && !atomic_load(&operation.done));
        CHECK(pthread_kill(thread, SIGUSR1) == 0);
        for (unsigned attempt = 0; !atomic_load(&operation.done); attempt++)
            CHECK(attempt < 2000 && usleep(1000) == 0);
        CHECK(pthread_join(thread, NULL) == 0 && interrupted == 1 && operation.result > 0 &&
              (size_t)operation.result < size);
        memset(bytes, '!', size);
        free(bytes);
        CHECK(close(pair[0]) == 0);
        CHECK(receive_pattern(pair[1], operation.result) == (size_t)operation.result &&
              close(pair[1]) == 0);
    }
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    puts("TCP_SEND_SIGNALS_PASS cases=2 writev sendmsg partial_bytes sa_restart_on_off owned_queue "
         "exact_eof");
}

static void send_nonblocking(void) {
    const size_t size = 262149;
    for (unsigned flag = 0; flag < 2; flag++) {
        int pair[2];
        limited_pair(pair);
        if (!flag)
            CHECK(fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK) == 0);
        uint8_t* bytes = send_pattern(size);
        ssize_t count = send(pair[0], bytes, size, MSG_NOSIGNAL | (flag ? MSG_DONTWAIT : 0));
        CHECK(count > 0 && (size_t)count < size);
        memset(bytes, '!', size);
        free(bytes);
        CHECK(close(pair[0]) == 0);
        CHECK(receive_pattern(pair[1], count) == (size_t)count && close(pair[1]) == 0);
    }
    puts("TCP_SEND_NONBLOCKING_PASS cases=2 o_nonblock msg_dontwait partial_bytes owned_queue "
         "exact_eof");
}

static uint8_t wire_byte(size_t position, unsigned lane, unsigned phase) {
    return pattern(position) ^ (phase * 73) ^ (lane * 11);
}

static void wire_send(int fd, unsigned lane, unsigned phase) {
    uint8_t bytes[4096];
    for (size_t position = 0; position < payload_bytes; position += sizeof(bytes)) {
        for (size_t at = 0; at < sizeof(bytes); at++)
            bytes[at] = wire_byte(position + at, lane, phase);
        send_all(fd, bytes, sizeof(bytes));
    }
    CHECK(shutdown(fd, SHUT_WR) == 0);
}

static void wire_receive(int fd, unsigned lane, unsigned phase) {
    uint8_t bytes[8192];
    size_t position = 0;
    for (;;) {
        ssize_t count = recv(fd, bytes, sizeof(bytes), 0);
        CHECK(count >= 0);
        if (!count)
            break;
        for (ssize_t at = 0; at < count; at++, position++)
            CHECK(position < payload_bytes && bytes[at] == wire_byte(position, lane, phase));
    }
    CHECK(position == payload_bytes);
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = {.sin_family = AF_INET,
                                    .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
        memcpy(&request.ifr_addr, &value, sizeof(value));
        CHECK(ioctl(fd, SIOCSIFADDR, &request) == 0);
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        CHECK(ioctl(fd, SIOCSIFNETMASK, &request) == 0 && ioctl(fd, SIOCGIFFLAGS, &request) == 0);
        request.ifr_flags |= IFF_UP;
        CHECK(ioctl(fd, SIOCSIFFLAGS, &request) == 0);
    }
    CHECK(close(fd) == 0);
    puts("TCP_CONFIG_PASS nics=2");
}

static void wire(unsigned lane, unsigned port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    timeouts(fd);
    struct sockaddr_in peer = {.sin_family = AF_INET,
                               .sin_port = htons(port),
                               .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    CHECK(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0);
    wire_send(fd, lane, 1);
    wire_receive(fd, lane, 2);
    CHECK(close(fd) == 0);
    printf("TCP_NATIVE_SERVER_PASS index=%u bytes_each=%u\n", lane + 1, payload_bytes);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = htons(41000 + lane),
                                .sin_addr.s_addr = htonl(0x0a170102 + (lane << 8))};
    CHECK(bind(listener, (struct sockaddr*)&local, sizeof(local)) == 0 && listen(listener, 4) == 0);
    printf("TCP_SERVER_READY index=%u\n", lane + 1);
    fflush(stdout);
    fd = accept(listener, NULL, NULL);
    CHECK(fd >= 0 && close(listener) == 0);
    timeouts(fd);
    wire_receive(fd, lane, 3);
    wire_send(fd, lane, 4);
    CHECK(close(fd) == 0);
    printf("TCP_NATIVE_CLIENT_PASS index=%u bytes_each=%u\n", lane + 1, payload_bytes);
    fflush(stdout);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && !strcmp(argv[1], "--accept-exec-check")) {
        int minimum = atoi(argv[2]);
        CHECK(minimum >= 3 && minimum < 128);
        int fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, minimum);
        CHECK(fd == minimum && close(fd) == 0);
        return 0;
    }
    signal(SIGPIPE, SIG_IGN);
    alarm(60);
    creation();
    bindings();
    options();
    refused();
    vectors();
    wait_all();
    wait_all_signals();
    retained_reads();
    accept_descriptors();
    accept_reservation();
    accept_lifetime();
    accept_signals();
    accept_teardown(argv[0]);
    retained_sends();
    send_deadlines();
    send_signals();
    send_nonblocking();
    connection_cycles();
    fflush(stdout);
    loopback();
    if (argc == 4 && !strcmp(argv[1], "--wire")) {
        configure();
        for (unsigned lane = 0; lane < 2; lane++) {
            char* end;
            unsigned long port = strtoul(argv[lane + 2], &end, 10);
            CHECK(!*end && port > 0 && port <= 65535);
            wire(lane, port);
        }
        CHECK(usleep(100000) == 0);
    } else
        CHECK(argc == 1);
    puts("TCP_TEST_PASS");
    return 0;
}
