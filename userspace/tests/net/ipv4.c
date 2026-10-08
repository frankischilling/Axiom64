// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "IPV4_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

static unsigned checksum(const unsigned char* data, size_t length) {
    unsigned sum = 0;
    while (length > 1) {
        sum += ((unsigned)data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }
    if (length)
        sum += (unsigned)*data << 8;
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}

static void request_bytes(unsigned char request[64]) {
    memset(request, 0, 64);
    request[0] = 8;
    request[4] = 0x43;
    request[5] = 0x21;
    request[7] = 1;
    for (size_t i = 8; i < 64; i++)
        request[i] = (unsigned char)(i * 17);
    unsigned sum = checksum(request, 64);
    request[2] = sum >> 8;
    request[3] = sum;
}

static void exchange(int fd, const char* target, const unsigned char request[64],
                     const char* label) {
    struct sockaddr_in destination = {.sin_family = AF_INET};
    check(inet_pton(AF_INET, target, &destination.sin_addr) == 1, "echo destination");
    check(sendto(fd, request, 64, 0, (struct sockaddr*)&destination, sizeof(destination)) == 64,
          "loopback ICMP send");
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        struct pollfd poller = {.fd = fd, .events = POLLIN};
        check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "loopback idle readiness");
        unsigned char reply[2048];
        struct sockaddr_in source;
        socklen_t length = sizeof(source);
        ssize_t received =
            recvfrom(fd, reply, sizeof(reply), 0, (struct sockaddr*)&source, &length);
        check(received >= 28 && length == sizeof(source) && source.sin_family == AF_INET &&
                  source.sin_port == 0 && source.sin_addr.s_addr == destination.sin_addr.s_addr,
              "raw IPv4 source metadata");
        if (reply[20] != 0)
            continue;
        // Raw ICMP sockets also expose packets rejected by the ICMP handler.
        if (checksum(reply + 20, (size_t)received - 20))
            continue;
        check(received == 84 && reply[0] == 0x45 && reply[9] == IPPROTO_ICMP &&
                  checksum(reply, 20) == 0 && checksum(reply + 20, 64) == 0,
              "loopback IPv4 and ICMP checksums");
        check(reply[21] == 0 && !memcmp(reply + 24, request + 4, 60), "loopback echo payload");
        if (label)
            puts(label);
        return;
    }
    check(0, "loopback echo reply");
}

static void echo(int fd, const char* target, const char* label) {
    unsigned char request[64];
    request_bytes(request);
    exchange(fd, target, request, label);
}

static void contracts(void) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "nonblocking raw ICMP socket");
    unsigned filter = ~1u;
    check(setsockopt(fd, 255, 1, &filter, sizeof(filter)) == 0, "ICMP echo-reply filter");
    struct sockaddr_in endpoint = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001)};
    check(connect(fd, (struct sockaddr*)&endpoint, sizeof(endpoint)) == 0,
          "raw ICMP loopback connect");
    struct sockaddr_in local, peer;
    socklen_t length = sizeof(local);
    check(getsockname(fd, (struct sockaddr*)&local, &length) == 0 && length == sizeof(local) &&
              local.sin_family == AF_INET && local.sin_port == htons(IPPROTO_ICMP) &&
              local.sin_addr.s_addr == endpoint.sin_addr.s_addr,
          "connected raw local address");
    length = sizeof(peer);
    check(getpeername(fd, (struct sockaddr*)&peer, &length) == -1 && errno == ENOTCONN,
          "zero-port raw peer query");
    endpoint.sin_port = htons(IPPROTO_ICMP);
    check(connect(fd, (struct sockaddr*)&endpoint, sizeof(endpoint)) == 0,
          "raw peer port metadata reconnect");
    check(getpeername(fd, (struct sockaddr*)&peer, &length) == 0 && length == sizeof(peer) &&
              peer.sin_family == AF_INET && peer.sin_port == htons(IPPROTO_ICMP) &&
              peer.sin_addr.s_addr == endpoint.sin_addr.s_addr,
          "connected raw peer address");
    unsigned char request[64], buffer[84];
    request_bytes(request);
    check(recv(fd, buffer, sizeof(buffer), 0) == -1 && errno == EAGAIN, "empty raw receive");
    struct iovec vectors[2] = {{request, 7}, {request + 7, sizeof(request) - 7}};
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    check(epoll >= 0, "raw ICMP epoll create");
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u64 = 0x49505634};
    check(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event) == 0, "raw ICMP epoll register");
    check(sendmsg(fd, &message, 0) == sizeof(request), "gathered raw ICMP send");
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "raw receive readiness");
    check(epoll_wait(epoll, &event, 1, 3000) == 1 && (event.events & EPOLLIN) &&
              event.data.u64 == 0x49505634 && epoll_wait(epoll, &event, 1, 0) == 0,
          "raw ICMP edge readiness and event metadata");
    int available = 0;
    check(ioctl(fd, FIONREAD, &available) == 0 && available == 84, "raw queued packet length");
    check(readv(fd, NULL, 0) == 0 && ioctl(fd, FIONREAD, &available) == 0 && available == 84,
          "empty vector read retains raw packet");
    check(recv(fd, buffer, 8, MSG_PEEK | MSG_TRUNC) == 84 && buffer[0] == 0x45,
          "raw peek returns original packet length");
    vectors[0] = (struct iovec){buffer, 5};
    vectors[1] = (struct iovec){buffer + 5, 7};
    message = (struct msghdr){
        .msg_name = &peer, .msg_namelen = sizeof(peer), .msg_iov = vectors, .msg_iovlen = 2};
    check(recvmsg(fd, &message, MSG_PEEK) == 12 && (message.msg_flags & MSG_TRUNC) &&
              message.msg_namelen == sizeof(peer) &&
              peer.sin_addr.s_addr == endpoint.sin_addr.s_addr,
          "raw scatter, metadata, and truncation flag");
    struct iovec bad = {(void*)1, sizeof(buffer)};
    message = (struct msghdr){.msg_iov = &bad, .msg_iovlen = 1};
    check(recvmsg(fd, &message, MSG_PEEK) == -1 && errno == EFAULT &&
              ioctl(fd, FIONREAD, &available) == 0 && available == 84,
          "failed peek copy retains raw packet");
    check(recvmsg(fd, &message, 0) == -1 && errno == EFAULT &&
              ioctl(fd, FIONREAD, &available) == 0 && available == 0,
          "failed non-peek raw receive copy consumes packet");
    check(send(fd, request, sizeof(request), 0) == sizeof(request), "send after raw receive fault");
    poller.revents = 0;
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "receive after raw copy fault");
    check(recv(fd, buffer, sizeof(buffer), 0) == sizeof(buffer) && checksum(buffer, 20) == 0 &&
              checksum(buffer + 20, 64) == 0 && buffer[20] == 0 &&
              !memcmp(buffer + 24, request + 4, 60),
          "raw packet copy and consumption");
    check(recv(fd, buffer, sizeof(buffer), 0) == -1 && errno == EAGAIN,
          "filtered request and consumed reply");
    check(close(epoll) == 0, "raw ICMP epoll close");
    check(send(fd, request, sizeof(request), 0) == sizeof(request), "connected raw send");
    poller.revents = 0;
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "duplicate packet readiness");
    int retained = dup(fd);
    check(retained >= 0 && close(fd) == 0 &&
              recv(retained, buffer, sizeof(buffer), 0) == sizeof(buffer),
          "raw duplicate retains queued packet");
    pid_t child = fork();
    check(child >= 0, "raw socket fork");
    if (!child) {
        check(send(retained, request, sizeof(request), 0) == sizeof(request), "inherited raw send");
        struct pollfd inherited = {.fd = retained, .events = POLLIN};
        check(poll(&inherited, 1, 3000) == 1 && (inherited.revents & POLLIN) &&
                  recv(retained, buffer, sizeof(buffer), 0) == sizeof(buffer) && buffer[20] == 0 &&
                  !memcmp(buffer + 24, request + 4, 60),
              "inherited raw receive");
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "raw socket child exit");
    check(recv(retained, buffer, sizeof(buffer), 0) == -1 && errno == EAGAIN,
          "raw inherited shared receive queue");
    struct sockaddr unspecified = {0};
    check(connect(retained, &unspecified, sizeof(unspecified)) == 0 &&
              getpeername(retained, (struct sockaddr*)&peer, &length) == -1 && errno == ENOTCONN,
          "raw disconnect");
    check(close(retained) == 0, "raw duplicate close");
    puts("IPV4_RAW_CONTRACT_PASS");
}

static void checksum_contract(void) {
    int receiver = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    int observer = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(receiver >= 0 && observer >= 0, "raw checksum observation sockets");
    unsigned filter = ~(1u << 8), replies = ~1u;
    check(setsockopt(receiver, 255, 1, &filter, sizeof(filter)) == 0 &&
              setsockopt(observer, 255, 1, &replies, sizeof(replies)) == 0,
          "raw checksum observation filters");
    struct sockaddr_in destination = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001)};
    unsigned char bytes[64], packet[84];
    request_bytes(bytes);
    bytes[2] ^= 1;
    check(sendto(receiver, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                 sizeof(destination)) == sizeof(bytes),
          "raw ICMP invalid checksum send");
    struct pollfd poller = {.fd = receiver, .events = POLLIN};
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN) &&
              recv(receiver, packet, sizeof(packet), 0) == sizeof(packet) &&
              checksum(packet, 20) == 0 && checksum(packet + 20, 64) != 0 &&
              !memcmp(packet + 20, bytes, sizeof(bytes)),
          "raw delivery before ICMP checksum rejection");
    poller.fd = observer;
    check(poll(&poller, 1, 100) == 0, "invalid ICMP checksum has no kernel echo reply");
    check(close(receiver) == 0 && close(observer) == 0, "checksum observation close");
    puts("IPV4_RAW_CHECKSUM_PASS");
}

static void queues(void) {
    int active = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    int lag = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(active >= 0 && lag >= 0, "independent raw listeners");
    unsigned filter = ~1u;
    check(setsockopt(active, 255, 1, &filter, sizeof(filter)) == 0 &&
              setsockopt(lag, 255, 1, &filter, sizeof(filter)) == 0,
          "independent echo reply filters");
    struct sockaddr_in destination = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001)};
    unsigned char bytes[64], packet[84];
    for (unsigned i = 0; i < 48; i++) {
        request_bytes(bytes);
        bytes[7] = i;
        bytes[2] = bytes[3] = 0;
        unsigned sum = checksum(bytes, sizeof(bytes));
        bytes[2] = sum >> 8;
        bytes[3] = sum;
        check(sendto(active, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                     sizeof(destination)) == sizeof(bytes),
              "listener pressure echo send");
        struct pollfd poller = {.fd = active, .events = POLLIN};
        check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN) &&
                  recv(active, packet, sizeof(packet), 0) == sizeof(packet) && packet[20] == 0 &&
                  checksum(packet + 20, 64) == 0 && !memcmp(packet + 24, bytes + 4, 60),
              "active listener unaffected by lagging queue");
    }
    for (unsigned i = 0; i < 32; i++)
        check(recv(lag, packet, sizeof(packet), 0) == sizeof(packet) && packet[27] == i,
              "bounded lagging listener order");
    check(recv(lag, packet, sizeof(packet), 0) == -1 && errno == EAGAIN,
          "lagging listener drops newest frames at capacity");
    const size_t payload_length = 20000, packet_length = payload_length + 20;
    unsigned char* large = malloc(payload_length);
    unsigned char* received = malloc(packet_length);
    check(large && received, "raw byte quota buffers");
    for (unsigned i = 0; i < 4; i++) {
        memset(large, i + 1, payload_length);
        large[0] = 8;
        large[1] = large[2] = large[3] = 0;
        large[4] = 0x51;
        large[5] = 0x42;
        large[6] = 0;
        large[7] = i;
        unsigned sum = checksum(large, payload_length);
        large[2] = sum >> 8;
        large[3] = sum;
        check(sendto(active, large, payload_length, 0, (struct sockaddr*)&destination,
                     sizeof(destination)) == (ssize_t)payload_length,
              "large local ICMP send");
        struct pollfd poller = {.fd = active, .events = POLLIN};
        check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN) &&
                  recv(active, received, packet_length, 0) == (ssize_t)packet_length &&
                  checksum(received, 20) == 0 && checksum(received + 20, payload_length) == 0 &&
                  !memcmp(received + 24, large + 4, payload_length - 4),
              "large active listener payload");
    }
    for (unsigned i = 0; i < 3; i++)
        check(recv(lag, received, packet_length, 0) == (ssize_t)packet_length && received[27] == i,
              "raw listener byte quota");
    check(recv(lag, received, packet_length, 0) == -1 && errno == EAGAIN,
          "raw listener bytes bounded independently of packet count");
    free(large);
    free(received);
    check(close(active) == 0 && close(lag) == 0, "independent listener cleanup");
    puts("IPV4_RX_QUEUE_PASS");
}

static void set_address(int fd, const char* name, unsigned request, const char* value) {
    struct ifreq interface = {0};
    strcpy(interface.ifr_name, name);
    struct sockaddr_in* address = (struct sockaddr_in*)&interface.ifr_addr;
    address->sin_family = AF_INET;
    check(inet_pton(AF_INET, value, &address->sin_addr) == 1, "static address parse");
    check(ioctl(fd, request, &interface) == 0, "static address configuration");
}

static void configuration(void) {
    check(if_nametoindex("eth0") == 1 && if_nametoindex("eth1") == 2, "libc interface name lookup");
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "IPv4 configuration descriptor");
    int type = 0;
    socklen_t length = sizeof(type);
    check(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 && type == SOCK_DGRAM,
          "configuration socket type");
    struct ifreq interface = {0};
    strcpy(interface.ifr_name, "lo");
    check(ioctl(fd, SIOCGIFADDR, &interface) == 0 &&
              ((struct sockaddr_in*)&interface.ifr_addr)->sin_addr.s_addr == htonl(0x7f000001),
          "loopback interface address");
    struct ifconf list = {0};
    check(ioctl(fd, SIOCGIFCONF, &list) == 0 && list.ifc_len == sizeof(struct ifreq),
          "initial address enumeration");
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[16], address[32], broadcast[32];
        snprintf(name, sizeof(name), "eth%u", lane);
        snprintf(address, sizeof(address), "10.23.%u.2", lane + 1);
        snprintf(broadcast, sizeof(broadcast), "10.23.%u.255", lane + 1);
        set_address(fd, name, SIOCSIFADDR, address);
        set_address(fd, name, SIOCSIFNETMASK, "255.255.255.0");
        memset(&interface, 0, sizeof(interface));
        strcpy(interface.ifr_name, name);
        struct sockaddr_in* mask = (struct sockaddr_in*)&interface.ifr_netmask;
        mask->sin_family = AF_INET;
        mask->sin_addr.s_addr = htonl(0xff00ff00);
        check(ioctl(fd, SIOCSIFNETMASK, &interface) == -1 && errno == EINVAL,
              "noncontiguous netmask rejection");
        check(ioctl(fd, SIOCGIFNETMASK, &interface) == 0 &&
                  ((struct sockaddr_in*)&interface.ifr_netmask)->sin_addr.s_addr ==
                      htonl(0xffffff00),
              "invalid netmask leaves configuration intact");
        memset(&interface, 0, sizeof(interface));
        strcpy(interface.ifr_name, name);
        check(ioctl(fd, SIOCGIFBRDADDR, &interface) == 0, "broadcast address query");
        struct in_addr expected;
        check(inet_pton(AF_INET, broadcast, &expected) == 1 &&
                  ((struct sockaddr_in*)&interface.ifr_broadaddr)->sin_addr.s_addr ==
                      expected.s_addr,
              "computed broadcast address");
        check(ioctl(fd, SIOCGIFFLAGS, &interface) == 0, "interface flags");
        interface.ifr_flags |= IFF_UP;
        check(ioctl(fd, SIOCSIFFLAGS, &interface) == 0, "interface administrative up");
    }
    list = (struct ifconf){0};
    check(ioctl(fd, SIOCGIFCONF, &list) == 0 && list.ifc_len == 3 * sizeof(struct ifreq),
          "configured address enumeration size");
    struct ifreq entries[3];
    list.ifc_buf = (char*)entries;
    check(ioctl(fd, SIOCGIFCONF, &list) == 0 && list.ifc_len == sizeof(entries),
          "configured address enumeration contents");
    check(!strcmp(entries[0].ifr_name, "eth0") && !strcmp(entries[1].ifr_name, "eth1") &&
              !strcmp(entries[2].ifr_name, "lo"),
          "stable address enumeration");
    struct rtentry route = {0};
    ((struct sockaddr_in*)&route.rt_dst)->sin_family = AF_INET;
    ((struct sockaddr_in*)&route.rt_genmask)->sin_family = AF_INET;
    struct sockaddr_in* gateway = (struct sockaddr_in*)&route.rt_gateway;
    gateway->sin_family = AF_INET;
    gateway->sin_addr.s_addr = htonl(0x0a170101);
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = "eth0";
    check(ioctl(fd, SIOCADDRT, &route) == 0, "default route add");
    check(ioctl(fd, SIOCADDRT, &route) == -1 && errno == EEXIST, "duplicate route rejection");
    check(ioctl(fd, SIOCDELRT, &route) == 0, "default route remove");
    check(ioctl(fd, SIOCDELRT, &route) == -1 && errno == ESRCH, "missing route rejection");
    gateway->sin_addr.s_addr = htonl(0x0a180101);
    check(ioctl(fd, SIOCADDRT, &route) == -1 && errno == ENETUNREACH, "gateway must be on link");
    gateway->sin_addr.s_addr = htonl(0x0a170101);
    struct sockaddr_in* mask = (struct sockaddr_in*)&route.rt_genmask;
    struct sockaddr_in* destination = (struct sockaddr_in*)&route.rt_dst;
    mask->sin_addr.s_addr = htonl(0xff00ff00);
    check(ioctl(fd, SIOCADDRT, &route) == -1 && errno == EINVAL,
          "noncontiguous route mask rejection");
    mask->sin_addr.s_addr = htonl(0xffffff00);
    destination->sin_addr.s_addr = htonl(0x0a630001);
    check(ioctl(fd, SIOCADDRT, &route) == -1 && errno == EINVAL,
          "route destination must match prefix");
    destination->sin_addr.s_addr = htonl(0x0a630000);
    destination->sin_family = AF_UNIX;
    check(ioctl(fd, SIOCADDRT, &route) == -1 && errno == EAFNOSUPPORT,
          "route address family rejection");
    check(close(fd) == 0, "configuration descriptor close");
    puts("IPV4_CONFIG_PASS");
}

static void route_change(int fd, unsigned request, const char* destination, const char* mask,
                         const char* gateway, const char* device, int metric) {
    struct rtentry route = {0};
    struct sockaddr_in* addresses[] = {(struct sockaddr_in*)&route.rt_dst,
                                       (struct sockaddr_in*)&route.rt_genmask,
                                       (struct sockaddr_in*)&route.rt_gateway};
    const char* text[] = {destination, mask, gateway};
    for (unsigned i = 0; i < 3; i++) {
        addresses[i]->sin_family = AF_INET;
        check(inet_pton(AF_INET, text[i], &addresses[i]->sin_addr) == 1, "route address parse");
    }
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = (char*)device;
    route.rt_metric = metric;
    check(ioctl(fd, request, &route) == 0, "route configuration");
}

static void routing(int fd) {
    route_change(fd, SIOCADDRT, "0.0.0.0", "0.0.0.0", "10.23.1.1", NULL, 0);
    echo(fd, "172.19.0.4", "IPV4_DEFAULT_ROUTE_PASS");
    route_change(fd, SIOCADDRT, "10.99.0.0", "255.255.0.0", "10.23.2.1", "eth1", 6);
    echo(fd, "10.99.1.1", "IPV4_PREFIX_ROUTE_PASS");
    route_change(fd, SIOCADDRT, "10.99.1.1", "255.255.255.255", "10.23.1.1", "eth0", 10);
    echo(fd, "10.99.1.1", "IPV4_HOST_ROUTE_PASS");
    route_change(fd, SIOCDELRT, "10.99.1.1", "255.255.255.255", "10.23.1.1", "eth0", 10);
    echo(fd, "10.99.1.1", "IPV4_ROUTE_REMOVE_PASS");
    route_change(fd, SIOCADDRT, "10.99.0.0", "255.255.0.0", "10.23.1.1", "eth0", 2);
    echo(fd, "10.99.1.1", "IPV4_ROUTE_METRIC_PASS");
    route_change(fd, SIOCDELRT, "10.99.0.0", "255.255.0.0", "10.23.1.1", "eth0", 2);
    route_change(fd, SIOCDELRT, "10.99.0.0", "255.255.0.0", "10.23.2.1", "eth1", 6);
    route_change(fd, SIOCDELRT, "0.0.0.0", "0.0.0.0", "10.23.1.1", NULL, 0);
    puts("IPV4_ROUTING_PASS");
}

struct Sender {
    int fd;
    atomic_int started, done;
    ssize_t result;
    unsigned char bytes[64], poison[64];
    struct sockaddr_in destination;
    struct iovec vectors[2];
    struct msghdr message;
};

static void* blocked_sender(void* pointer) {
    struct Sender* sender = pointer;
    atomic_store(&sender->started, 1);
    sender->result = sendmsg(sender->fd, &sender->message, 0);
    atomic_store(&sender->done, 1);
    return NULL;
}

static void pressure_bytes(unsigned char bytes[64], unsigned sequence) {
    request_bytes(bytes);
    bytes[4] = 0x50;
    bytes[5] = 0x52;
    bytes[6] = sequence >> 8;
    bytes[7] = sequence;
    for (unsigned i = 8; i < 64; i++)
        bytes[i] = (unsigned char)(i * 17 + sequence);
    bytes[2] = bytes[3] = 0;
    unsigned sum = checksum(bytes, 64);
    bytes[2] = sum >> 8;
    bytes[3] = sum;
}

static void pressure(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "IPv4 pressure socket");
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(0x0a170103 + (lane << 8))};
    unsigned char bytes[64];
    for (unsigned sequence = 0; sequence < 32; sequence++) {
        pressure_bytes(bytes, sequence);
        check(sendto(fd, bytes, sizeof(bytes), MSG_DONTWAIT, (struct sockaddr*)&destination,
                     sizeof(destination)) == sizeof(bytes),
              "bounded IPv4 output acceptance");
    }
    check(sendto(fd, bytes, sizeof(bytes), MSG_DONTWAIT, (struct sockaddr*)&destination,
                 sizeof(destination)) == -1 &&
              errno == EAGAIN,
          "IPv4 output backpressure");
    struct pollfd poller = {.fd = fd, .events = POLLOUT};
    check(poll(&poller, 1, 0) == 0, "full IPv4 output is not writable");
    struct Sender sender = {.fd = fd, .destination = destination};
    pressure_bytes(sender.bytes, 32);
    sender.vectors[0] = (struct iovec){sender.bytes, 13};
    sender.vectors[1] = (struct iovec){sender.bytes + 13, sizeof(sender.bytes) - 13};
    sender.message = (struct msghdr){.msg_name = &sender.destination,
                                     .msg_namelen = sizeof(sender.destination),
                                     .msg_iov = sender.vectors,
                                     .msg_iovlen = 2};
    pthread_t thread;
    check(pthread_create(&thread, NULL, blocked_sender, &sender) == 0, "blocked raw sender create");
    while (!atomic_load(&sender.started))
        usleep(1000);
    usleep(50000);
    check(!atomic_load(&sender.done), "raw sender actually blocked");
    check(close(fd) == 0, "close blocked sender descriptor");
    int replacement = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(replacement >= 0, "replacement raw socket");
    if (replacement != fd) {
        check(dup2(replacement, fd) == fd && close(replacement) == 0,
              "reuse raw sender descriptor");
        replacement = fd;
    }
    char other[16];
    snprintf(other, sizeof(other), "eth%u", lane ^ 1);
    check(setsockopt(replacement, SOL_SOCKET, SO_BINDTODEVICE, other, strlen(other) + 1) == 0,
          "replacement interface binding");
    memset(sender.bytes, 0xa5, sizeof(sender.bytes));
    sender.destination.sin_addr.s_addr = htonl(0x0a170201);
    sender.vectors[0] = (struct iovec){sender.poison, 0};
    sender.vectors[1] = (struct iovec){sender.poison, 0};
    sender.message.msg_name = sender.poison;
    sender.message.msg_namelen = 0;
    sender.message.msg_iov = NULL;
    sender.message.msg_iovlen = 0;
    printf("IPV4_PRESSURE_RELEASE index=%u\n", lane + 1);
    check(pthread_join(thread, NULL) == 0 && sender.result == 64,
          "retained raw send description, payload, and metadata");
    check(close(replacement) == 0, "replacement raw sender close");
    printf("IPV4_PRESSURE_PASS index=%u\n", lane + 1);
}

static double monotonic(void) {
    struct timespec now;
    check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic IPv4 clock");
    return now.tv_sec + now.tv_nsec / 1000000000.0;
}

static void arp_failure(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "ARP failure socket");
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_port = htons(IPPROTO_ICMP),
                                      .sin_addr.s_addr = htonl(0x0a170163 + (lane << 8))};
    check(connect(fd, (struct sockaddr*)&destination, sizeof(destination)) == 0,
          "ARP failure connected route");
    unsigned char bytes[64];
    request_bytes(bytes);
    double started = monotonic();
    check(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "unresolved IPv4 output accepted");
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 5000) == 1 && (poller.revents & POLLERR), "bounded idle ARP failure");
    double elapsed = monotonic() - started;
    check(elapsed >= 2.5 && elapsed <= 4.5, "ARP retry deadline");
    int error;
    socklen_t length = sizeof(error);
    check(syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR, (void*)1, &length) == -1 &&
              errno == EFAULT,
          "failed error copy");
    poller.revents = 0;
    check(poll(&poller, 1, 0) == 1 && (poller.revents & POLLERR),
          "failed error copy preserves error");
    length = sizeof(error);
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == EHOSTUNREACH,
          "ARP failure socket error");
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error,
          "socket error read resets state");
    check(recv(fd, bytes, sizeof(bytes), 0) == -1 && errno == EAGAIN,
          "failed ARP produces no receive packet");
    check(close(fd) == 0, "ARP failure close");
    printf("IPV4_ARP_FAILURE_PASS index=%u elapsed_ms=%u\n", lane + 1, (unsigned)(elapsed * 1000));
}

static void icmp_error(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "ICMP error socket");
    unsigned filter = ~0u;
    check(setsockopt(fd, 255, 1, &filter, sizeof(filter)) == 0, "filter raw ICMP error payloads");
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_port = htons(IPPROTO_ICMP),
                                      .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    check(connect(fd, (struct sockaddr*)&destination, sizeof(destination)) == 0,
          "ICMP error route connect");
    unsigned char bytes[64];
    request_bytes(bytes);
    bytes[4] = 0x45;
    bytes[5] = 0x52;
    bytes[2] = bytes[3] = 0;
    unsigned sum = checksum(bytes, sizeof(bytes));
    bytes[2] = sum >> 8;
    bytes[3] = sum;
    check(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "ICMP error quoted request");
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 100) == 0, "malformed and mismatched ICMP quotes ignored");
    printf("IPV4_ICMP_ERROR_RELEASE index=%u\n", lane + 1);
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLERR), "ICMP hard error readiness");
    int error;
    socklen_t length = sizeof(error);
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == EMSGSIZE,
          "ICMP fragmentation-needed socket error");
    check(recv(fd, bytes, sizeof(bytes), 0) == -1 && errno == EAGAIN,
          "ICMP filter independent from error delivery");
    check(close(fd) == 0, "ICMP error socket close");
    printf("IPV4_ICMP_ERROR_PASS index=%u\n", lane + 1);
}

static void incoming(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "incoming ICMP socket");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "incoming ICMP interface filter");
    unsigned filter = ~(1u << 8);
    check(setsockopt(fd, 255, 1, &filter, sizeof(filter)) == 0, "incoming echo-request filter");
    printf("IPV4_INPUT_READY index=%u\n", lane + 1);
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN), "idle incoming echo readiness");
    unsigned char packet[84];
    struct sockaddr_in source;
    socklen_t length = sizeof(source);
    check(recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&source, &length) ==
                  sizeof(packet) &&
              length == sizeof(source) && source.sin_family == AF_INET && source.sin_port == 0 &&
              source.sin_addr.s_addr == htonl(0x0a170101 + (lane << 8)) &&
              checksum(packet, 20) == 0 && checksum(packet + 20, 64) == 0 && packet[20] == 8 &&
              packet[24] == 0x48 && packet[25] == 0x49 && packet[26] == 0 && packet[27] == lane,
          "incoming host echo source, header, and marker");
    for (unsigned i = 8; i < 64; i++)
        check(packet[20 + i] == (unsigned char)(i * 11 + lane), "incoming host echo payload");
    check(close(fd) == 0, "incoming ICMP close");
    printf("IPV4_INPUT_PASS index=%u\n", lane + 1);
}

static void cache_expiry(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "ARP cache expiry socket");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "cache expiry interface");
    printf("IPV4_CACHE_EXPIRY_READY index=%u\n", lane + 1);
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN),
          "cache expiry host acknowledgement");
    unsigned char packet[84];
    check(recv(fd, packet, sizeof(packet), 0) == sizeof(packet) && packet[20] == 0 &&
              packet[24] == 'E' && packet[25] == 'X' && packet[27] == lane + 1 &&
              checksum(packet, 20) == 0 && checksum(packet + 20, 64) == 0,
          "cache expiry acknowledgement bytes");
    check(close(fd) == 0, "cache acknowledgement close");
    fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "expired-neighbor output socket");
    char target[32];
    snprintf(target, sizeof(target), "10.23.%u.1", lane + 1);
    echo(fd, target, "IPV4_CACHE_ECHO_PASS");
    check(close(fd) == 0, "expired-neighbor output close");
    printf("IPV4_CACHE_EXPIRY_PASS index=%u\n", lane + 1);
}

static void limits(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "IPv4 limits socket");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "IPv4 limits interface");
    int ttl = 0;
    check(setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1 && errno == EINVAL,
          "zero TTL rejection");
    ttl = 255;
    check(setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0, "maximum TTL");
    socklen_t length = sizeof(ttl);
    check(getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &length) == 0 && ttl == 255, "TTL option query");
    ttl = 64;
    check(setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0, "restore wire TTL");
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    unsigned char oversized[1481] = {8}, bytes[64];
    check(sendto(fd, oversized, sizeof(oversized), 0, (struct sockaddr*)&destination,
                 sizeof(destination)) == -1 &&
              errno == EMSGSIZE,
          "IPv4 MTU includes header");
    destination.sin_addr.s_addr = htonl(0xffffffff);
    request_bytes(bytes);
    bytes[4] = 'B';
    bytes[5] = 'C';
    bytes[2] = bytes[3] = 0;
    unsigned sum = checksum(bytes, sizeof(bytes));
    bytes[2] = sum >> 8;
    bytes[3] = sum;
    check(sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                 sizeof(destination)) == -1 &&
              errno == EACCES,
          "broadcast permission flag");
    int enabled = 1;
    check(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(enabled)) == 0 &&
              sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                     sizeof(destination)) == sizeof(bytes),
          "explicit limited broadcast output");
    check(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &enabled, sizeof(enabled)) == -1 &&
              errno == ENOPROTOOPT,
          "unsupported raw IP header option");
    check(listen(fd, 1) == -1 && errno == EOPNOTSUPP, "unsupported raw stream lifecycle");
    check(close(fd) == 0, "IPv4 limits close");
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    check(control >= 0 &&
              sendto(control, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                     sizeof(destination)) == -1 &&
              errno == EOPNOTSUPP && recv(control, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 &&
              errno == EOPNOTSUPP,
          "UDP control descriptor rejects unimplemented data I/O");
    check(close(control) == 0, "UDP control close");
    check(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) == -1 && errno == EPROTONOSUPPORT &&
              socket(AF_INET, SOCK_RAW, IPPROTO_UDP) == -1 && errno == EPROTONOSUPPORT,
          "unimplemented Internet protocols are explicit");
    printf("IPV4_LIMITS_PASS index=%u\n", lane + 1);
}

struct Receiver {
    int fd;
    atomic_int started, done;
    ssize_t result;
    unsigned char bytes[84], poison[84];
    struct sockaddr_in source;
    struct iovec vectors[2];
    struct msghdr message;
};

static void* blocked_receiver(void* pointer) {
    struct Receiver* receiver = pointer;
    atomic_store(&receiver->started, 1);
    receiver->result = recvmsg(receiver->fd, &receiver->message, 0);
    atomic_store(&receiver->done, 1);
    return NULL;
}

static void receive_lifetime(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "blocked raw receiver socket");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "blocked receiver interface");
    struct Receiver receiver = {.fd = fd};
    receiver.vectors[0] = (struct iovec){receiver.bytes, 13};
    receiver.vectors[1] = (struct iovec){receiver.bytes + 13, sizeof(receiver.bytes) - 13};
    receiver.message = (struct msghdr){.msg_name = &receiver.source,
                                       .msg_namelen = sizeof(receiver.source),
                                       .msg_iov = receiver.vectors,
                                       .msg_iovlen = 2};
    pthread_t thread;
    check(pthread_create(&thread, NULL, blocked_receiver, &receiver) == 0,
          "blocked raw receiver create");
    while (!atomic_load(&receiver.started))
        usleep(1000);
    usleep(50000);
    check(!atomic_load(&receiver.done), "raw receiver actually blocked");
    int original = dup(fd);
    check(original >= 0 && close(fd) == 0, "retain original raw receiver description");
    int replacement = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(replacement >= 0, "replacement raw receiver socket");
    if (replacement != fd) {
        check(dup2(replacement, fd) == fd && close(replacement) == 0,
              "reuse raw receiver descriptor");
        replacement = fd;
    }
    snprintf(name, sizeof(name), "eth%u", lane ^ 1);
    check(setsockopt(replacement, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "replacement receiver interface");
    receiver.vectors[0] = (struct iovec){receiver.poison, 0};
    receiver.vectors[1] = (struct iovec){receiver.poison, 0};
    receiver.message.msg_name = receiver.poison;
    receiver.message.msg_namelen = 0;
    receiver.message.msg_iov = NULL;
    receiver.message.msg_iovlen = 0;
    unsigned char bytes[64];
    request_bytes(bytes);
    bytes[4] = 'L';
    bytes[5] = 'R';
    bytes[2] = bytes[3] = 0;
    unsigned sum = checksum(bytes, sizeof(bytes));
    bytes[2] = sum >> 8;
    bytes[3] = sum;
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    check(sendto(original, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                 sizeof(destination)) == sizeof(bytes) &&
              close(original) == 0,
          "wake raw receiver with only retained I/O ownership");
    check(pthread_join(thread, NULL) == 0 && receiver.result == sizeof(receiver.bytes) &&
              receiver.bytes[20] == 0 && checksum(receiver.bytes, 20) == 0 &&
              checksum(receiver.bytes + 20, 64) == 0 && !memcmp(receiver.bytes + 24, bytes + 4, 60),
          "retained raw receive payload");
    check(receiver.message.msg_namelen == sizeof(receiver.source) && !receiver.message.msg_flags &&
              receiver.source.sin_family == AF_INET && receiver.source.sin_port == 0 &&
              receiver.source.sin_addr.s_addr == destination.sin_addr.s_addr &&
              !memcmp(receiver.poison, (unsigned char[84]){0}, sizeof(receiver.poison)),
          "captured raw receive vectors and source metadata");
    check(recv(replacement, receiver.bytes, sizeof(receiver.bytes), 0) == -1 && errno == EAGAIN,
          "replacement raw receiver untouched");
    check(close(replacement) == 0, "replacement receiver close");
    printf("IPV4_RECEIVE_LIFETIME_PASS index=%u\n", lane + 1);
}

static void device_fault(void) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5) == 0,
          "failed-device raw socket binding");
    struct sockaddr_in destination = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x0a170101)};
    unsigned char bytes[64];
    request_bytes(bytes);
    puts("IPV4_FAULT_READY");
    check(sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                 sizeof(destination)) == sizeof(bytes),
          "failed-device pending output");
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLERR),
          "failed device wakes raw socket");
    check(recv(fd, bytes, sizeof(bytes), 0) == -1 && errno == EIO &&
              sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                     sizeof(destination)) == -1 &&
              errno == EIO,
          "failed device raw receive and send errors");
    int error;
    socklen_t length = sizeof(error);
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == EIO,
          "permanent raw device error state");
    check(close(fd) == 0, "failed device raw close");
    fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "other interface remains available");
    echo(fd, "10.23.2.1", "IPV4_OTHER_NIC_PASS");
    check(close(fd) == 0, "other-interface raw close");
    puts("IPV4_DEVICE_FAULT_PASS");
}

static void cache_replacement(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "ARP replacement raw socket");
    char name[16], target[32];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "ARP replacement interface");
    for (unsigned sequence = 0; sequence < 132; sequence++) {
        if (sequence == 131) {
            int listener = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x0806));
            struct sockaddr_ll address = {.sll_family = AF_PACKET,
                                          .sll_protocol = htons(0x0806),
                                          .sll_ifindex = (int)lane + 1};
            check(listener >= 0 && bind(listener, (struct sockaddr*)&address, sizeof(address)) == 0,
                  "ARP peer refresh listener");
            printf("IPV4_CACHE_REFRESH_READY index=%u\n", lane + 1);
            struct pollfd poller = {.fd = listener, .events = POLLIN};
            check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN),
                  "ARP peer refresh readiness");
            unsigned char frame[60];
            check(recv(listener, frame, sizeof(frame), 0) == sizeof(frame) && frame[20] == 0 &&
                      frame[21] == 1 && frame[31] == 139 && frame[22] == 2 && frame[26] == 2 &&
                      frame[27] == 139,
                  "ARP refreshed peer request bytes");
            check(close(listener) == 0, "ARP refresh listener close");
        }
        unsigned last = sequence < 129    ? sequence + 10 + (sequence >= 89)
                        : sequence == 130 ? 10
                                          : 139;
        snprintf(target, sizeof(target), "10.23.%u.%u", lane + 1, last);
        unsigned char request[64];
        request_bytes(request);
        request[4] = 'C';
        request[5] = 'R';
        request[6] = sequence >> 8;
        request[7] = sequence;
        request[2] = request[3] = 0;
        unsigned sum = checksum(request, sizeof(request));
        request[2] = sum >> 8;
        request[3] = sum;
        exchange(fd, target, request, NULL);
        // Distinguish least-recently-used entries even on a fast host.
        usleep(10000);
    }
    check(close(fd) == 0, "ARP replacement raw close");
    printf("IPV4_CACHE_REPLACEMENT_PASS index=%u neighbors=129\n", lane + 1);
}

static void arp_reply_pressure(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    unsigned filter = ~1u;
    check(fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0 &&
              setsockopt(fd, 255, 1, &filter, sizeof(filter)) == 0,
          "ARP reply pressure acknowledgement socket");
    int listener = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x0806));
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET, .sll_protocol = htons(0x0806), .sll_ifindex = (int)lane + 1};
    int ignore = 1;
    check(listener >= 0 && bind(listener, (struct sockaddr*)&address, sizeof(address)) == 0 &&
              setsockopt(listener, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore, sizeof(ignore)) ==
                  0,
          "ARP reply pressure ingress listener");
    printf("IPV4_ARP_REPLY_READY index=%u\n", lane + 1);
    for (unsigned received = 0; received < 96; received++) {
        struct pollfd poller = {.fd = listener, .events = POLLIN};
        check(poll(&poller, 1, 5000) == 1 && (poller.revents & POLLIN),
              "ARP reply pressure ingress readiness");
        unsigned char frame[60];
        check(recv(listener, frame, sizeof(frame), 0) == sizeof(frame) && frame[20] == 0 &&
                  frame[21] == (received ? 3 : 1) && frame[22] == 2 && frame[25] == lane &&
                  frame[26] == 1 && frame[27] == received + 140 && frame[31] == received + 140,
              "ARP reply pressure ingress bytes");
        if ((received + 1) % 8 == 0)
            printf("IPV4_ARP_REPLY_RX index=%u frames=%u\n", lane + 1, received + 1);
    }
    check(close(listener) == 0, "ARP reply pressure ingress close");
    for (unsigned phase = 0; phase < 2; phase++) {
        struct pollfd poller = {.fd = fd, .events = POLLIN};
        check(poll(&poller, 1, 5000) == 1 && (poller.revents & POLLIN),
              "ARP reply pressure acknowledgement readiness");
        unsigned char packet[84];
        struct sockaddr_in source;
        socklen_t length = sizeof(source);
        check(recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&source, &length) ==
                      sizeof(packet) &&
                  length == sizeof(source) &&
                  source.sin_addr.s_addr == htonl(0x0a170101 + (lane << 8)) &&
                  checksum(packet, 20) == 0 && checksum(packet + 20, 64) == 0 && packet[20] == 0 &&
                  packet[24] == 'A' && packet[25] == (phase ? 'Q' : 'P') && packet[26] == 0 &&
                  packet[27] == lane + 1,
              "ARP reply pressure acknowledgement bytes");
        if (!phase)
            printf("IPV4_ARP_REPLY_RELEASE index=%u\n", lane + 1);
    }
    check(close(fd) == 0, "ARP reply pressure close");
    printf("IPV4_ARP_REPLY_PASS index=%u\n", lane + 1);
}

static void link_change(unsigned lane) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "link-change raw socket");
    struct ifreq interface = {0};
    snprintf(interface.ifr_name, sizeof(interface.ifr_name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface.ifr_name,
                     strlen(interface.ifr_name) + 1) == 0,
          "link-change bound interface");
    for (unsigned up = 0; up < 2; up++) {
        printf("IPV4_LINK_%s index=%u\n", up ? "UP" : "DOWN", lane + 1);
        double deadline = monotonic() + 3;
        do {
            check(ioctl(fd, SIOCGIFFLAGS, &interface) == 0, "link-change flags query");
            if (!!(interface.ifr_flags & IFF_RUNNING) == up)
                break;
            usleep(1000);
        } while (monotonic() < deadline);
        check((interface.ifr_flags & IFF_UP) && !!(interface.ifr_flags & IFF_RUNNING) == up,
              "carrier state independent from administrative state");
        if (!up) {
            unsigned char bytes[64];
            request_bytes(bytes);
            struct sockaddr_in destination = {.sin_family = AF_INET,
                                              .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
            check(sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                         sizeof(destination)) == -1 &&
                      errno == ENETDOWN,
                  "carrier loss rejects IPv4 output");
            int local = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
            check(local >= 0, "loopback during carrier loss");
            echo(local, "127.0.0.1", "IPV4_LINK_LOOPBACK_PASS");
            check(close(local) == 0, "carrier-loss loopback close");
        }
    }
    interface.ifr_flags &= ~IFF_UP;
    check(ioctl(fd, SIOCSIFFLAGS, &interface) == 0 && ioctl(fd, SIOCGIFFLAGS, &interface) == 0 &&
              !(interface.ifr_flags & IFF_UP) && (interface.ifr_flags & IFF_RUNNING),
          "administrative down preserves carrier");
    unsigned char bytes[64];
    request_bytes(bytes);
    struct sockaddr_in destination = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(0x0a170101 + (lane << 8))};
    check(sendto(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&destination,
                 sizeof(destination)) == -1 &&
              errno == ENETDOWN,
          "administrative down rejects IPv4 output");
    interface.ifr_flags |= IFF_UP;
    check(ioctl(fd, SIOCSIFFLAGS, &interface) == 0, "restore administrative up");
    char target[32];
    snprintf(target, sizeof(target), "10.23.%u.1", lane + 1);
    echo(fd, target, "IPV4_LINK_RECOVERY_ECHO_PASS");
    check(close(fd) == 0, "link-change raw close");
    printf("IPV4_LINK_PASS index=%u\n", lane + 1);
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    check(fd >= 0, "raw ICMP socket");
    echo(fd, "127.0.0.1", "IPV4_LOOPBACK_PASS");
    check(close(fd) == 0, "loopback socket close");
    contracts();
    checksum_contract();
    fd = -1;
    const char* fault = getenv("AXIOM64_IP_FAULT");
    if (fault && !strcmp(fault, "1")) {
        configuration();
        device_fault();
        puts("IPV4_SOCKET_PASS");
        return 0;
    }
    if (argc == 1 || strcmp(argv[1], "--loopback")) {
        queues();
        configuration();
        fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
        check(fd >= 0, "wire raw ICMP socket");
        set_address(fd, "eth0", SIOCSIFNETMASK, "255.255.255.255");
        echo(fd, "10.23.1.2", "IPV4_HOST_MASK_LOCAL_PASS");
        set_address(fd, "eth0", SIOCSIFNETMASK, "255.255.255.0");
        echo(fd, "10.23.1.2", "IPV4_LOCAL_ADDRESS_PASS");
        echo(fd, "10.23.1.1", "IPV4_WIRE_VIRTIO_PASS");
        echo(fd, "10.23.2.1", "IPV4_WIRE_E1000_PASS");
        check(close(fd) == 0, "initial wire socket close");
        fd = -1;
        cache_expiry(0);
        cache_expiry(1);
        fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
        check(fd >= 0, "routed wire socket");
        routing(fd);
        pressure(0);
        pressure(1);
        arp_failure(0);
        arp_failure(1);
        icmp_error(0);
        icmp_error(1);
        incoming(0);
        incoming(1);
        limits(0);
        limits(1);
        receive_lifetime(0);
        receive_lifetime(1);
        link_change(0);
        link_change(1);
        cache_replacement(0);
        cache_replacement(1);
        arp_reply_pressure(0);
        arp_reply_pressure(1);
    }
    if (fd >= 0)
        check(close(fd) == 0, "raw ICMP close");
    puts("IPV4_SOCKET_PASS");
    return 0;
}
