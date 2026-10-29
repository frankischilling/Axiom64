// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void check(int condition, const char* operation) {
    if (!condition) {
        int error = errno;
        printf("TCP6_LOCAL_FAIL operation=%s errno=%d\n", operation, error);
        exit(1);
    }
}

static void ready(int fd, short events) {
    struct pollfd item = {.fd = fd, .events = events};
    check(poll(&item, 1, 5000) == 1 && (item.revents & events), "bounded actual stream readiness");
}

static int scalar(int fd, int level, int option) {
    int value = -1;
    socklen_t size = sizeof(value);
    check(!getsockopt(fd, level, option, &value, &size) && size == sizeof(value),
          "complete stream option result");
    return value;
}

static void option(int fd, int level, int name, int value) {
    check(!setsockopt(fd, level, name, &value, sizeof(value)), "stream option update");
}

static int listener(int only, int wildcard, struct sockaddr_in6* address) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
    check(fd >= 0, "IPv6 TCP socket creation");
    check(scalar(fd, SOL_SOCKET, SO_DOMAIN) == AF_INET6 &&
              scalar(fd, SOL_SOCKET, SO_TYPE) == SOCK_STREAM &&
              scalar(fd, SOL_SOCKET, SO_PROTOCOL) == IPPROTO_TCP,
          "IPv6 TCP descriptor identity");
    option(fd, IPPROTO_IPV6, IPV6_V6ONLY, only);
    memset(address, 0, sizeof(*address));
    address->sin6_family = AF_INET6;
    address->sin6_addr = wildcard ? in6addr_any : in6addr_loopback;
    check(!bind(fd, (struct sockaddr*)address, sizeof(*address)), "IPv6 TCP bind");
    socklen_t size = sizeof(*address);
    check(!getsockname(fd, (struct sockaddr*)address, &size) && size == sizeof(*address) &&
              address->sin6_family == AF_INET6 && address->sin6_port && !address->sin6_scope_id,
          "IPv6 TCP bound address");
    errno = 0;
    check(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only)) == -1 && errno == EINVAL,
          "bound TCP description rejects V6ONLY replacement");
    check(scalar(fd, IPPROTO_IPV6, IPV6_V6ONLY) == only, "failed V6ONLY update preserves state");
    check(!listen(fd, 4) && scalar(fd, SOL_SOCKET, SO_ACCEPTCONN) == 1, "IPv6 TCP listen");
    return fd;
}

static void stream(int mapped) {
    struct sockaddr_in6 address;
    int server = listener(!mapped, mapped, &address);
    int client = socket(mapped ? AF_INET : AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    check(client >= 0, "client TCP socket creation");
    struct sockaddr_in four = {.sin_family = AF_INET, .sin_port = address.sin6_port};
    four.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin6_addr = in6addr_loopback;
    errno = 0;
    int connected = mapped ? connect(client, (struct sockaddr*)&four, sizeof(four))
                           : connect(client, (struct sockaddr*)&address, sizeof(address));
    check(!connected || (connected == -1 && errno == EINPROGRESS), "nonblocking TCP connect");
    ready(server, POLLIN);
    errno = 0;
    check(accept4(server, NULL, NULL, 0x40000000) == -1 && errno == EINVAL,
          "invalid accept flags preserve queued connection");
    struct sockaddr_in6 peer;
    memset(&peer, 0xa5, sizeof(peer));
    socklen_t size = sizeof(peer);
    int accepted = accept4(server, (struct sockaddr*)&peer, &size, SOCK_CLOEXEC | SOCK_NONBLOCK);
    check(accepted >= 0 && size == sizeof(peer) && peer.sin6_family == AF_INET6 && peer.sin6_port &&
              !peer.sin6_scope_id,
          "IPv6 TCP accept4 and peer address");
    struct in6_addr expected = in6addr_loopback;
    if (mapped)
        check(inet_pton(AF_INET6, "::ffff:127.0.0.1", &expected) == 1, "mapped peer fixture");
    check(!memcmp(&peer.sin6_addr, &expected, sizeof(expected)), "actual accepted IPv6 peer");
    check((fcntl(accepted, F_GETFL) & O_NONBLOCK) && (fcntl(accepted, F_GETFD) & FD_CLOEXEC),
          "accepted descriptor flags");
    ready(client, POLLOUT);
    check(scalar(client, SOL_SOCKET, SO_ERROR) == 0, "actual TCP connect completion");
    option(accepted, IPPROTO_TCP, TCP_NODELAY, 1);
    check(scalar(accepted, IPPROTO_TCP, TCP_NODELAY) == 1, "accepted TCP_NODELAY");
    int alias = fcntl(client, F_DUPFD_CLOEXEC, 0);
    check(alias >= 0 && !close(client), "shared TCP descriptor survives original close");
    client = alias;
    uint8_t request[513], received[513];
    for (size_t at = 0; at < sizeof(request); at++)
        request[at] = (uint8_t)(at * 29 + mapped);
    struct iovec sent[] = {{request, 127}, {request + 127, sizeof(request) - 127}};
    check(writev(client, sent, 2) == sizeof(request), "actual vector stream output");
    ready(accepted, POLLIN);
    check(recv(accepted, received, sizeof(received), MSG_PEEK) == sizeof(received) &&
              !memcmp(received, request, sizeof(received)),
          "stream peeking preserves every byte");
    memset(received, 0, sizeof(received));
    struct iovec vectors[] = {{received, 129}, {received + 129, sizeof(received) - 129}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    check(recvmsg(accepted, &message, MSG_DONTWAIT) == sizeof(received) &&
              !memcmp(received, request, sizeof(received)),
          "actual vector stream input");
    check(!shutdown(client, SHUT_WR), "TCP client write shutdown");
    ready(accepted, POLLIN);
    check(recv(accepted, received, sizeof(received), 0) == 0, "peer observes actual FIN EOF");
    const char reply[] = "TCP6 reply after EOF";
    check(send(accepted, reply, sizeof(reply), 0) == sizeof(reply), "reply after peer FIN");
    check(!shutdown(accepted, SHUT_WR), "TCP server write shutdown");
    ready(client, POLLIN);
    check(recv(client, received, sizeof(received), 0) == sizeof(reply) &&
              !memcmp(received, reply, sizeof(reply)),
          "complete reply after write shutdown");
    ready(client, POLLIN);
    check(recv(client, received, sizeof(received), 0) == 0, "client observes actual server FIN");
    check(!close(accepted) && !close(client) && !close(server), "complete stream retirement");
    printf("TCP6_LOCAL_STREAM_PASS mapped=%d request=%zu reply=%zu\n", mapped, sizeof(request),
           sizeof(reply));
}

static void port_ownership(int only) {
    struct sockaddr_in6 address;
    int server = listener(only, 1, &address);
    int four = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(four >= 0, "port ownership IPv4 socket");
    struct sockaddr_in bound = {.sin_family = AF_INET, .sin_port = address.sin6_port};
    errno = 0;
    int result = bind(four, (struct sockaddr*)&bound, sizeof(bound));
    check(only ? result == 0 : result == -1 && errno == EADDRINUSE,
          "dual-stack wildcard and V6ONLY TCP port ownership");
    check(!close(four) && !close(server), "port ownership retirement");
    printf("TCP6_LOCAL_PORT_PASS v6only=%d\n", only);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    stream(0);
    stream(1);
    port_ownership(0);
    port_ownership(1);
    puts("TCP6_LOCAL_PASS streams=2 port_owners=2");
    return 0;
}
