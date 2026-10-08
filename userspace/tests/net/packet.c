// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROTOCOL 0x88b5
static const unsigned char peer[6] = {2, 0x41, 0x58, 0x50, 0x4b, 0};

static void check(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "PACKET_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

static int raw(int index, int protocol, int flags) {
    int fd = socket(AF_PACKET, SOCK_RAW | flags, htons(protocol));
    check(fd >= 0, "socket");
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET, .sll_protocol = htons(protocol), .sll_ifindex = index};
    check(bind(fd, (struct sockaddr*)&address, sizeof(address)) == 0, "bind");
    return fd;
}

static void frame(unsigned char* bytes, size_t length, const unsigned char mac[6], unsigned lane,
                  unsigned sequence) {
    memcpy(bytes, peer, 6);
    bytes[5] = lane;
    memcpy(bytes + 6, mac, 6);
    bytes[12] = PROTOCOL >> 8;
    bytes[13] = PROTOCOL & 255;
    memcpy(bytes + 14, "AX64", 4);
    bytes[18] = lane;
    bytes[19] = sequence >> 24;
    bytes[20] = sequence >> 16;
    bytes[21] = sequence >> 8;
    bytes[22] = sequence;
    for (size_t i = 23; i < length; i++)
        bytes[i] = (unsigned char)(sequence + i * 13 + lane * 7);
}

static void received(const unsigned char* bytes, const unsigned char* sent, size_t length,
                     const struct sockaddr_ll* address, const unsigned char mac[6], int index) {
    unsigned char expected[1518];
    memcpy(expected, sent, length);
    memcpy(expected, mac, 6);
    memcpy(expected + 6, peer, 6);
    expected[11] = sent[18];
    check(!memcmp(bytes, expected, length), "host frame bytes");
    if (address)
        check(address->sll_family == AF_PACKET && address->sll_protocol == htons(PROTOCOL) &&
                  address->sll_ifindex == index && address->sll_hatype == 1 &&
                  address->sll_halen == 6 && address->sll_pkttype == PACKET_HOST &&
                  !memcmp(address->sll_addr, expected + 6, 6),
              "host frame metadata");
}

static void link_state(int control, struct ifreq* request, int index) {
    printf("PACKET_LINK_DOWN index=%d\n", index);
    unsigned retries = 0;
    do {
        check(ioctl(control, SIOCGIFFLAGS, request) == 0, "carrier query down");
        if (!(request->ifr_flags & IFF_RUNNING))
            break;
        usleep(10000);
    } while (++retries < 300);
    check((request->ifr_flags & IFF_UP) && !(request->ifr_flags & IFF_RUNNING),
          "physical down preserves admin up");
    int fd = raw(index, PROTOCOL, SOCK_NONBLOCK);
    unsigned char bytes[64] = {0};
    check(write(fd, bytes, sizeof(bytes)) == -1 && errno == ENETDOWN, "carrier down TX");
    check(close(fd) == 0, "carrier down socket close");
    printf("PACKET_LINK_UP index=%d\n", index);
    retries = 0;
    do {
        check(ioctl(control, SIOCGIFFLAGS, request) == 0, "carrier query up");
        if (request->ifr_flags & IFF_RUNNING)
            break;
        usleep(10000);
    } while (++retries < 300);
    check((request->ifr_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING),
          "physical carrier recovery");
    printf("PACKET_LINK_PASS index=%d\n", index);
}

static void listener_pressure(int fd, int index, const unsigned char mac[6], unsigned sequence) {
    int lagger = raw(index, PROTOCOL, SOCK_NONBLOCK), one = 1;
    check(setsockopt(lagger, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)) == 0,
          "lagging listener ignore outgoing");
    unsigned char sent[64], bytes[1518];
    for (unsigned i = 0; i < 48; i++) {
        frame(sent, sizeof(sent), mac, index - 1, sequence + i);
        check(write(fd, sent, sizeof(sent)) == sizeof(sent) &&
                  read(fd, bytes, sizeof(bytes)) == sizeof(sent),
              "active listener during pressure");
        received(bytes, sent, sizeof(sent), NULL, mac, index);
    }

    struct {
        unsigned packets, drops;
    } stats;

    socklen_t length = sizeof(stats);
    check(getsockopt(lagger, SOL_PACKET, PACKET_STATISTICS, &stats, &length) == 0 &&
              length == sizeof(stats) && stats.packets == 48 && stats.drops == 16,
          "bounded independent listener drops");
    for (unsigned i = 0; i < 32; i++) {
        frame(sent, sizeof(sent), mac, index - 1, sequence + i);
        check(read(lagger, bytes, sizeof(bytes)) == sizeof(sent),
              "lagging listener retained frame");
        received(bytes, sent, sizeof(sent), NULL, mac, index);
    }
    check(read(lagger, bytes, sizeof(bytes)) == -1 && errno == EAGAIN, "lagging listener drained");
    length = sizeof(stats);
    check(getsockopt(lagger, SOL_PACKET, PACKET_STATISTICS, &stats, &length) == 0 &&
              !stats.packets && !stats.drops,
          "packet statistics reset");
    check(close(lagger) == 0, "lagging listener close");
}

struct BlockedReceive {
    int fd;
    atomic_int started, done;
    ssize_t result;
    unsigned char bytes[1518], poison[1518];
    struct sockaddr_ll source;
    struct iovec vectors[2];
    struct msghdr message;
};

static void* blocked_receive(void* data) {
    struct BlockedReceive* work = data;
    atomic_store(&work->started, 1);
    work->result = recvmsg(work->fd, &work->message, 0);
    atomic_store(&work->done, 1);
    return NULL;
}

static int retained_receive(int fd, int index, const unsigned char mac[6], unsigned sequence) {
    struct BlockedReceive work = {.fd = fd};
    work.vectors[0] = (struct iovec){work.bytes, 9};
    work.vectors[1] = (struct iovec){work.bytes + 9, sizeof(work.bytes) - 9};
    work.message = (struct msghdr){.msg_name = &work.source,
                                   .msg_namelen = sizeof(work.source),
                                   .msg_iov = work.vectors,
                                   .msg_iovlen = 2};
    pthread_t thread;
    check(pthread_create(&thread, NULL, blocked_receive, &work) == 0, "blocked receiver create");
    while (!atomic_load(&work.started))
        usleep(1000);
    usleep(50000);
    check(!atomic_load(&work.done), "receiver actually blocked");
    int original = dup(fd);
    check(original >= 0 && close(fd) == 0, "blocked description retained");
    int replacement = raw(index, 0, SOCK_NONBLOCK);
    if (replacement != fd) {
        check(dup2(replacement, fd) == fd && close(replacement) == 0, "reuse blocked descriptor");
        replacement = fd;
    }
    work.vectors[0] = (struct iovec){work.poison, 0};
    work.vectors[1] = (struct iovec){work.poison, 0};
    work.message.msg_iov = NULL;
    work.message.msg_iovlen = 0;
    work.message.msg_name = work.poison;
    work.message.msg_namelen = 0;
    unsigned char sent[64], bytes[1518];
    frame(sent, sizeof(sent), mac, index - 1, sequence);
    check(write(original, sent, sizeof(sent)) == sizeof(sent), "wake original packet description");
    check(pthread_join(thread, NULL) == 0 && work.result == sizeof(sent),
          "retained receiver completion");
    received(work.bytes, sent, sizeof(sent), &work.source, mac, index);
    check(work.message.msg_namelen == sizeof(work.source) && !work.message.msg_flags &&
              !memcmp(work.poison, (unsigned char[1518]){0}, sizeof(work.poison)),
          "captured receive metadata");
    check(read(replacement, bytes, sizeof(bytes)) == -1 && errno == EAGAIN,
          "replacement queue untouched");
    check(close(replacement) == 0, "replacement close");
    pid_t child = fork();
    check(child >= 0, "packet fork");
    if (!child) {
        frame(sent, sizeof(sent), mac, index - 1, sequence + 1);
        check(write(original, sent, sizeof(sent)) == sizeof(sent) &&
                  read(original, bytes, sizeof(bytes)) == sizeof(sent),
              "inherited packet description");
        received(bytes, sent, sizeof(sent), NULL, mac, index);
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "packet child exit");
    return original;
}

static void nic(int control, int index, unsigned sequences) {
    struct ifreq request = {0};
    request.ifr_ifindex = index;
    check(ioctl(control, SIOCGIFNAME, &request) == 0, "interface name");
    check(ioctl(control, SIOCGIFINDEX, &request) == 0 && request.ifr_ifindex == index,
          "interface index");
    check(ioctl(control, SIOCGIFMTU, &request) == 0 && request.ifr_mtu == 1500, "MTU");
    check(ioctl(control, SIOCGIFHWADDR, &request) == 0 && request.ifr_hwaddr.sa_family == 1, "MAC");
    unsigned char mac[6];
    memcpy(mac, request.ifr_hwaddr.sa_data, 6);
    check(ioctl(control, SIOCGIFFLAGS, &request) == 0 && !(request.ifr_flags & IFF_UP),
          "initial admin state");
    request.ifr_flags |= IFF_UP;
    check(ioctl(control, SIOCSIFFLAGS, &request) == 0, "admin up");
    check(ioctl(control, SIOCGIFFLAGS, &request) == 0 && (request.ifr_flags & IFF_UP) &&
              (request.ifr_flags & IFF_RUNNING),
          "carrier");
    link_state(control, &request, index);
    int fd = raw(index, PROTOCOL, SOCK_CLOEXEC), observer = raw(index, PROTOCOL, SOCK_NONBLOCK);
    int disabled = raw(index, 0, SOCK_NONBLOCK), other = raw(index, PROTOCOL + 1, SOCK_NONBLOCK);
    int one = 1;
    check(setsockopt(observer, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)) == 0,
          "ignore outgoing");
    check(fcntl(fd, F_GETFD) & FD_CLOEXEC, "close-on-exec");
    check(fcntl(observer, F_GETFL) & O_NONBLOCK, "nonblocking");
    struct stat stat;
    check(fstat(fd, &stat) == 0 && S_ISSOCK(stat.st_mode), "socket stat");
    int kind = 0;
    socklen_t kind_length = sizeof(kind);
    check(getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &kind_length) == 0 && kind == SOCK_RAW,
          "socket type");
    unsigned char sent[1518], bytes[1518];
    check(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN, "empty queue");
    struct sockaddr_ll local = {0};
    socklen_t local_length = sizeof(local);
    check(getsockname(fd, (struct sockaddr*)&local, &local_length) == 0 &&
              local.sll_ifindex == index && local.sll_protocol == htons(PROTOCOL) &&
              local_length == 18 && !memcmp(local.sll_addr, mac, 6),
          "socket address");
    check(connect(fd, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EOPNOTSUPP,
          "unsupported connect");
    frame(sent, 1515, mac, index - 1, 0);
    check(write(fd, sent, 13) == -1 && errno == EINVAL, "short TX rejected");
    check(write(fd, sent, 1515) == -1 && errno == EMSGSIZE, "oversized TX rejected");
    check(send(fd, sent, 64, MSG_OOB) == -1 && errno == EOPNOTSUPP, "unsupported TX flags");
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    check(epoll >= 0, "epoll create");
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x123456789abcdef0ull};
    check(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event) == 0, "epoll add");
    // Keep enough independent frames in flight to cross the 16-bit queue
    // indices without turning every frame into a timer-paced round trip.
    for (unsigned base = 0; base < sequences; base += 16) {
        unsigned end = sequences - base < 16 ? sequences : base + 16;
        for (unsigned sequence = base; sequence < end; sequence++) {
            size_t length = sequence % 7 == 6 ? 1514 : 64 + (sequence % 6) * 31;
            frame(sent, length, mac, index - 1, sequence);
            if (sequence % 3 == 0)
                check(write(fd, sent, length) == (ssize_t)length, "descriptor TX");
            else if (sequence % 3 == 1) {
                struct iovec vectors[3] = {{sent, 5}, {sent + 5, 0}, {sent + 5, length - 5}};
                struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 3};
                check(sendmsg(fd, &message, 0) == (ssize_t)length, "vector TX");
            } else {
                struct sockaddr_ll destination = {
                    .sll_family = AF_PACKET, .sll_ifindex = index, .sll_protocol = htons(PROTOCOL)};
                check(sendto(fd, sent, length, 0, (struct sockaddr*)&destination,
                             sizeof(destination)) == (ssize_t)length,
                      "addressed TX");
            }
        }
        for (unsigned sequence = base; sequence < end; sequence++) {
            size_t length = sequence % 7 == 6 ? 1514 : 64 + (sequence % 6) * 31;
            frame(sent, length, mac, index - 1, sequence);
            check(epoll_wait(epoll, &event, 1, 3000) == 1 && (event.events & EPOLLIN) &&
                      event.data.u64 == 0x123456789abcdef0ull,
                  "epoll RX while tasks blocked");
            struct pollfd poller = {.fd = fd, .events = POLLIN};
            check(poll(&poller, 1, 0) == 1 && (poller.revents & POLLIN), "poll RX");
            int available = 0;
            check(ioctl(fd, FIONREAD, &available) == 0 && available == (int)length,
                  "next packet length");
            check(recv(fd, bytes, 7, MSG_PEEK | MSG_TRUNC) == (ssize_t)length &&
                      !memcmp(bytes, mac, 6),
                  "peek truncated length");
            struct sockaddr_ll source;
            socklen_t source_length = sizeof(source);
            if (sequence % 3 == 0) {
                check(recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&source,
                               &source_length) == (ssize_t)length &&
                          source_length == sizeof(source),
                      "addressed RX");
                received(bytes, sent, length, &source, mac, index);
            } else if (sequence % 3 == 1) {
                struct iovec vectors[2] = {{bytes, 11}, {bytes + 11, sizeof(bytes) - 11}};
                struct msghdr message = {.msg_name = &source,
                                         .msg_namelen = sizeof(source),
                                         .msg_iov = vectors,
                                         .msg_iovlen = 2};
                check(recvmsg(fd, &message, 0) == (ssize_t)length && message.msg_flags == 0 &&
                          message.msg_namelen == sizeof(source),
                      "vector RX");
                received(bytes, sent, length, &source, mac, index);
            } else {
                check(read(fd, bytes, sizeof(bytes)) == (ssize_t)length, "descriptor RX");
                received(bytes, sent, length, NULL, mac, index);
            }
            check(recv(observer, bytes, sizeof(bytes), 0) == (ssize_t)length,
                  "independent listener");
            received(bytes, sent, length, NULL, mac, index);
            check(recv(disabled, bytes, sizeof(bytes), 0) == -1 && errno == EAGAIN,
                  "zero protocol filter");
            check(recv(other, bytes, sizeof(bytes), 0) == -1 && errno == EAGAIN, "protocol filter");
        }
        check(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN,
              "whole frames consumed");
    }
    check(close(epoll) == 0 && close(observer) == 0 && close(disabled) == 0 && close(other) == 0,
          "listener close");
    listener_pressure(fd, index, mac, sequences);
    int duplicate = dup(fd);
    check(duplicate >= 0 && close(fd) == 0, "duplicate lifetime");
    frame(sent, 64, mac, index - 1, sequences + 48);
    check(write(duplicate, sent, 64) == 64 && read(duplicate, bytes, sizeof(bytes)) == 64,
          "I/O after original close");
    received(bytes, sent, 64, NULL, mac, index);
    duplicate = retained_receive(duplicate, index, mac, sequences + 49);
    check(close(duplicate) == 0, "last socket close");
    check(ioctl(control, SIOCGIFFLAGS, &request) == 0, "read flags");
    request.ifr_flags &= ~IFF_UP;
    check(ioctl(control, SIOCSIFFLAGS, &request) == 0 &&
              ioctl(control, SIOCGIFFLAGS, &request) == 0 && !(request.ifr_flags & IFF_UP) &&
              (request.ifr_flags & IFF_RUNNING),
          "admin down preserves carrier");
    printf("PACKET_NIC_PASS index=%d frames=%u\n", index, sequences + 51);
}

static void fault_test(int bad_id) {
    int control = socket(AF_PACKET, SOCK_RAW, 0);
    check(control >= 0, "fault control socket");
    struct ifreq request = {.ifr_ifindex = 1};
    check(ioctl(control, SIOCGIFNAME, &request) == 0 &&
              ioctl(control, SIOCGIFHWADDR, &request) == 0,
          "fault interface discovery");
    unsigned char mac[6], sent[64], bytes[1518];
    memcpy(mac, request.ifr_hwaddr.sa_data, 6);
    request.ifr_flags = IFF_UP;
    check(ioctl(control, SIOCSIFFLAGS, &request) == 0, "fault interface up");
    int fd = raw(1, PROTOCOL, 0);
    frame(sent, sizeof(sent), mac, 0, 0);
    printf("PACKET_FAULT_READY mode=%s\n", bad_id ? "id" : "length");
    check(write(fd, sent, sizeof(sent)) == sizeof(sent), "fault trigger TX");
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    if (bad_id) {
        check(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLERR), "broken queue poll error");
        check(read(fd, bytes, sizeof(bytes)) == -1 && errno == EIO, "broken queue RX error");
        check(write(fd, sent, sizeof(sent)) == -1 && errno == EIO, "broken queue TX error");
    } else {
        check(poll(&poller, 1, 200) == 0, "malformed completion dropped");
        frame(sent, sizeof(sent), mac, 0, 1);
        check(write(fd, sent, sizeof(sent)) == sizeof(sent) &&
                  read(fd, bytes, sizeof(bytes)) == sizeof(sent),
              "RX recovery after malformed length");
        received(bytes, sent, sizeof(sent), NULL, mac, 1);
    }
    check(close(fd) == 0 && close(control) == 0, "fault socket teardown");
    printf("PACKET_FAULT_PASS mode=%s\n", bad_id ? "id" : "length");
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    if (argc > 1 && (!strcmp(argv[1], "fault-id") || !strcmp(argv[1], "fault-length"))) {
        fault_test(!strcmp(argv[1], "fault-id"));
        return 0;
    }
    unsigned sequences = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 16;
    check(sequences > 0 && sequences <= 100000, "frame count");
    int control = socket(AF_PACKET, SOCK_RAW, 0);
    check(control >= 0, "control socket");
    unsigned count = 0;
    for (int index = 1; index <= 8; index++) {
        struct ifreq request = {0};
        request.ifr_ifindex = index;
        if (ioctl(control, SIOCGIFNAME, &request) < 0) {
            check(errno == ENODEV, "discovery termination");
            break;
        }
        nic(control, index, sequences);
        count++;
    }
    check(count > 0, "at least one NIC");
    check(close(control) == 0, "control close");
    printf("PACKET_TESTS_PASS nics=%u\n", count);
    return 0;
}
