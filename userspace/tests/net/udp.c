// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

static void check(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "UDP_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

static struct sockaddr_in address(unsigned port, unsigned ip) {
    return (struct sockaddr_in){
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(ip)};
}

static int endpoint(unsigned ip, struct sockaddr_in* local) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    check(fd >= 0, "UDP creation");
    *local = address(0, ip);
    check(bind(fd, (struct sockaddr*)local, sizeof(*local)) == 0, "UDP bind ephemeral");
    socklen_t size = sizeof(*local);
    check(getsockname(fd, (struct sockaddr*)local, &size) == 0 && size == sizeof(*local) &&
              local->sin_family == AF_INET && local->sin_port != 0 &&
              local->sin_addr.s_addr == htonl(ip),
          "UDP bound name");
    return fd;
}

static void readable(int fd) {
    struct pollfd item = {.fd = fd, .events = POLLIN};
    check(poll(&item, 1, 2000) == 1 && (item.revents & POLLIN) && !(item.revents & POLLERR),
          "UDP receive readiness");
}

static void empty(int fd) {
    unsigned char byte;
    check(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN, "UDP queue empty");
}

static void bindings(void) {
    struct sockaddr_in local, peer;
    int fd = endpoint(0, &local);
    check((fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC),
          "UDP descriptor flags");
    int value = 0;
    socklen_t size = sizeof(value);
    check(getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &size) == 0 && value == SOCK_DGRAM,
          "UDP socket type");
    check(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &value, &size) == 0 && value == IPPROTO_UDP,
          "UDP socket protocol");
    check(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &value, &size) == 0 && value == AF_INET,
          "UDP socket domain");
    check(bind(fd, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EINVAL,
          "UDP already bound rejects rebind");
    int conflict = socket(AF_INET, SOCK_DGRAM, 0);
    peer = local;
    peer.sin_addr.s_addr = htonl(0x7f000001);
    check(bind(conflict, (struct sockaddr*)&peer, sizeof(peer)) == -1 && errno == EADDRINUSE,
          "wildcard UDP bind conflicts with specific address");
    int retained = dup(fd);
    check(retained >= 0, "UDP description duplicate");
    close(fd);
    check(bind(conflict, (struct sockaddr*)&peer, sizeof(peer)) == -1 && errno == EADDRINUSE,
          "UDP duplicate retains bound port");
    close(retained);
    check(bind(conflict, (struct sockaddr*)&peer, sizeof(peer)) == 0,
          "UDP final close releases bound port");
    struct sockaddr_in target = address(54321, 0x7f000001);
    check(connect(conflict, (struct sockaddr*)&target, sizeof(target)) == 0,
          "fixed UDP port connects");
    struct sockaddr disconnect = {.sa_family = AF_UNSPEC};
    check(connect(conflict, &disconnect, sizeof(disconnect)) == 0, "fixed UDP port disconnects");
    size = sizeof(local);
    check(getsockname(conflict, (struct sockaddr*)&local, &size) == 0 &&
              local.sin_port == peer.sin_port && local.sin_addr.s_addr == peer.sin_addr.s_addr,
          "UDP disconnect preserves explicitly bound address and port");
    close(conflict);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    peer = address(0, 0x0a630063);
    check(bind(fd, (struct sockaddr*)&peer, sizeof(peer)) == -1 && errno == EADDRNOTAVAIL,
          "UDP bind requires local address");
    close(fd);
    puts("UDP_BINDINGS_PASS");
}

static void zero_peer(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in peer = address(0, 0x7f000001), local, source;
    int sender = endpoint(0x7f000001, &source);
    check(fd >= 0 && connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0,
          "UDP zero-port connected peer");
    socklen_t size = sizeof(peer);
    check(getpeername(fd, (struct sockaddr*)&peer, &size) == -1 && errno == ENOTCONN &&
              getsockname(fd, (struct sockaddr*)&local, &size) == 0 && local.sin_port != 0 &&
              local.sin_addr.s_addr == htonl(0x7f000001),
          "UDP zero-port peer query and automatic local binding");
    check(sendto(sender, "any-port", 8, 0, (struct sockaddr*)&local, sizeof(local)) == 8,
          "UDP zero-port peer incoming source");
    readable(fd);
    char data[16];
    check(recv(fd, data, sizeof(data), 0) == 8 && !memcmp(data, "any-port", 8),
          "UDP zero-port peer keeps remote port wildcard");
    close(sender);
    close(fd);
    puts("UDP_ZERO_PEER_PASS");
}

static void reuse(void) {
    struct sockaddr_in local;
    int first = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int newest = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int specific = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0), value = 1;
    check(first >= 0 && newest >= 0 && specific >= 0 && sender >= 0, "UDP reuse sockets");
    check(setsockopt(first, SOL_SOCKET, SO_REUSEADDR, &value, 4) == 0 &&
              setsockopt(newest, SOL_SOCKET, SO_REUSEADDR, &value, 4) == 0 &&
              setsockopt(specific, SOL_SOCKET, SO_REUSEADDR, &value, 4) == 0,
          "UDP reuse option");
    local = address(0, 0);
    socklen_t size = sizeof(local);
    check(bind(first, (struct sockaddr*)&local, sizeof(local)) == 0 &&
              getsockname(first, (struct sockaddr*)&local, &size) == 0 &&
              bind(newest, (struct sockaddr*)&local, sizeof(local)) == 0,
          "UDP shared wildcard port");
    local.sin_addr.s_addr = htonl(0x7f000001);
    check(sendto(sender, "tie", 3, 0, (struct sockaddr*)&local, sizeof(local)) == 3,
          "UDP unicast shared port");
    readable(newest);
    char buffer[8];
    check(recv(newest, buffer, sizeof(buffer), 0) == 3 && !memcmp(buffer, "tie", 3),
          "UDP latest equal-specificity receiver");
    empty(first);
    check(bind(specific, (struct sockaddr*)&local, sizeof(local)) == 0, "UDP shared specific port");
    check(sendto(sender, "best", 4, 0, (struct sockaddr*)&local, sizeof(local)) == 4,
          "UDP specific destination");
    readable(specific);
    check(recv(specific, buffer, sizeof(buffer), 0) == 4 && !memcmp(buffer, "best", 4),
          "UDP specific bind wins unicast");
    empty(first);
    empty(newest);
    close(sender);
    close(specific);
    close(newest);
    close(first);
    puts("UDP_REUSE_PASS");
}

static void shutdowns(void) {
    for (int connected = 0; connected < 2; connected++)
        for (int how = 0; how < 3; how++) {
            struct sockaddr_in local, peer;
            int fd = endpoint(0x7f000001, &local), sender = endpoint(0x7f000001, &peer);
            if (connected)
                check(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0, "UDP shutdown peer");
            check(sendto(sender, "queued", 6, 0, (struct sockaddr*)&local, sizeof(local)) == 6,
                  "UDP queued before shutdown");
            readable(fd);
            int result = shutdown(fd, how);
            check(connected ? result == 0 : result == -1 && errno == ENOTCONN,
                  "UDP shutdown connected return policy");
            struct pollfd poller = {.fd = fd, .events = POLLIN | POLLOUT | POLLRDHUP};
            check(poll(&poller, 1, 0) == 1 && (poller.revents & POLLOUT) &&
                      ((poller.revents & POLLRDHUP) != 0) == (how != SHUT_WR) &&
                      ((poller.revents & POLLHUP) != 0) == (how == SHUT_RDWR),
                  "UDP shutdown readiness");
            char buffer[16];
            check(recv(fd, buffer, sizeof(buffer), 0) == 6 && !memcmp(buffer, "queued", 6),
                  "UDP shutdown preserves queued payload");
            empty(fd);
            check(sendto(sender, "later", 5, 0, (struct sockaddr*)&local, sizeof(local)) == 5,
                  "UDP incoming after shutdown");
            readable(fd);
            check(recv(fd, buffer, sizeof(buffer), 0) == 5 && !memcmp(buffer, "later", 5),
                  "UDP read shutdown retains later incoming datagrams");
            ssize_t sent = sendto(fd, "out", 3, 0, (struct sockaddr*)&peer, sizeof(peer));
            check(how == SHUT_RD ? sent == 3 : sent == -1 && errno == EPIPE,
                  "UDP write shutdown returns EPIPE without SIGPIPE");
            if (how != SHUT_WR) {
                check(fcntl(fd, F_SETFL, 0) == 0 && recv(fd, buffer, sizeof(buffer), 0) == 0,
                      "blocking empty UDP after read shutdown");
            }
            close(sender);
            close(fd);
        }
    puts("UDP_SHUTDOWN_PASS");
}

static void errors(void) {
    struct sockaddr_in closed;
    int holder = endpoint(0x7f000001, &closed);
    close(holder);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    check(fd >= 0 && connect(fd, (struct sockaddr*)&closed, sizeof(closed)) == 0,
          "UDP closed-port peer");
    check(send(fd, "error", 5, 0) == 5, "UDP accepts closed-port output");
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 2000) == 1 && (poller.revents & POLLERR),
          "UDP connected ICMP port error readiness");
    int error = 0;
    socklen_t size = sizeof(error);
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == ECONNREFUSED,
          "UDP connected ICMP port error");
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0,
          "UDP SO_ERROR clear");
    close(fd);
    struct timespec delay = {.tv_sec = 1, .tv_nsec = 100000000};
    nanosleep(&delay, NULL);
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    check(fd >= 0 && sendto(fd, "error", 5, 0, (struct sockaddr*)&closed, sizeof(closed)) == 5,
          "UDP unconnected closed-port output");
    poller = (struct pollfd){.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 100) == 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 &&
              error == 0,
          "default UDP unconnected ICMP errors ignored");
    close(fd);
    puts("UDP_ERRORS_PASS");
}

struct Receiver {
    int fd;
    atomic_int started, done;
    ssize_t result;
    int error;
    unsigned char bytes[31], poison[31];
    struct sockaddr_in source;
    struct iovec vectors[2];
    struct msghdr message;
};

static void* blocked_receiver(void* pointer) {
    struct Receiver* receiver = pointer;
    atomic_store(&receiver->started, 1);
    receiver->result = recvmsg(receiver->fd, &receiver->message, 0);
    receiver->error = errno;
    atomic_store(&receiver->done, 1);
    return NULL;
}

static void receive_lifetime(int poison_metadata) {
    struct sockaddr_in local, source;
    int fd = endpoint(0x7f000001, &local), sender = endpoint(0x7f000001, &source);
    check(fcntl(fd, F_SETFL, 0) == 0, "blocking UDP lifetime socket");
    struct Receiver receiver = {.fd = fd};
    receiver.vectors[0] = (struct iovec){receiver.bytes, 7};
    receiver.vectors[1] = (struct iovec){receiver.bytes + 7, sizeof(receiver.bytes) - 7};
    receiver.message = (struct msghdr){.msg_name = &receiver.source,
                                       .msg_namelen = sizeof(receiver.source),
                                       .msg_iov = receiver.vectors,
                                       .msg_iovlen = 2};
    pthread_t thread;
    check(pthread_create(&thread, NULL, blocked_receiver, &receiver) == 0, "UDP receiver thread");
    while (!atomic_load(&receiver.started))
        usleep(1000);
    usleep(50000);
    check(!atomic_load(&receiver.done), "UDP receive actually blocks");
    check(close(fd) == 0, "close blocked UDP descriptor");
    int replacement = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    check(replacement >= 0, "UDP replacement socket");
    if (replacement != fd) {
        check(dup2(replacement, fd) == fd && close(replacement) == 0,
              "reuse blocked UDP descriptor");
        replacement = fd;
    }
    check(bind(replacement, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EADDRINUSE,
          "retained UDP I/O alone retains original port");
    if (poison_metadata) {
        receiver.vectors[0] = (struct iovec){receiver.poison, 0};
        receiver.vectors[1] = (struct iovec){receiver.poison, 0};
        receiver.message.msg_name = receiver.poison;
        receiver.message.msg_namelen = 1;
        receiver.message.msg_iov = NULL;
        receiver.message.msg_iovlen = 0;
    }
    unsigned char payload[31];
    for (unsigned i = 0; i < sizeof(payload); i++)
        payload[i] = (unsigned char)(i * 13 + 7);
    check(sendto(sender, payload, sizeof(payload), 0, (struct sockaddr*)&local, sizeof(local)) ==
              sizeof(payload),
          "wake retained UDP port");
    check(pthread_join(thread, NULL) == 0 && receiver.result == sizeof(payload) &&
              !memcmp(receiver.bytes, payload, sizeof(payload)) &&
              receiver.source.sin_family == AF_INET &&
              receiver.source.sin_port == source.sin_port &&
              receiver.source.sin_addr.s_addr == source.sin_addr.s_addr &&
              receiver.message.msg_namelen == sizeof(receiver.source) &&
              !memcmp(receiver.poison, (unsigned char[31]){0}, sizeof(receiver.poison)),
          "retained UDP receive description, vectors and source metadata");
    check(bind(replacement, (struct sockaddr*)&local, sizeof(local)) == 0,
          "completed UDP I/O releases original port");
    empty(replacement);
    close(sender);
    close(replacement);
    puts(poison_metadata ? "UDP_CAPTURED_RECEIVE_PASS" : "UDP_RECEIVE_LIFETIME_PASS");
}

static volatile sig_atomic_t caught;

static void signal_handler(int signal) {
    (void)signal;
    caught = 1;
}

static void interrupted(int restart) {
    struct sockaddr_in local, replacement_local, source;
    int fd = endpoint(0x7f000001, &local), sender = endpoint(0x7f000001, &source);
    check(fcntl(fd, F_SETFL, 0) == 0, "UDP interrupted blocking socket");
    struct sigaction action = {.sa_handler = signal_handler, .sa_flags = restart ? SA_RESTART : 0};
    sigemptyset(&action.sa_mask);
    check(sigaction(SIGUSR1, &action, NULL) == 0, "UDP interruption handler");
    caught = 0;
    struct Receiver receiver = {.fd = fd};
    receiver.vectors[0] = (struct iovec){receiver.bytes, sizeof(receiver.bytes)};
    receiver.message = (struct msghdr){.msg_name = &receiver.source,
                                       .msg_namelen = sizeof(receiver.source),
                                       .msg_iov = receiver.vectors,
                                       .msg_iovlen = 1};
    pthread_t thread;
    check(pthread_create(&thread, NULL, blocked_receiver, &receiver) == 0,
          "UDP interrupted receiver thread");
    while (!atomic_load(&receiver.started))
        usleep(1000);
    usleep(50000);
    check(!atomic_load(&receiver.done) && close(fd) == 0,
          "UDP interruption starts from retained I/O alone");
    int replacement = endpoint(0x7f000001, &replacement_local);
    if (replacement != fd) {
        check(dup2(replacement, fd) == fd && close(replacement) == 0,
              "UDP interruption reuses descriptor");
        replacement = fd;
    }
    check(fcntl(replacement, F_SETFL, 0) == 0, "blocking UDP replacement description");
    int probe = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    check(probe >= 0 && bind(probe, (struct sockaddr*)&local, sizeof(local)) == -1 &&
              errno == EADDRINUSE,
          "UDP pre-handler request retains original port");
    check(pthread_kill(thread, SIGUSR1) == 0, "UDP caught signal delivery");
    for (unsigned attempt = 0; !caught && attempt < 1000; attempt++)
        usleep(1000);
    check(caught && bind(probe, (struct sockaddr*)&local, sizeof(local)) == 0,
          "UDP caught handler releases original retained port");
    if (restart) {
        check(sendto(sender, "old", 3, 0, (struct sockaddr*)&local, sizeof(local)) == 3,
              "UDP old port remains independently usable after restart");
        readable(probe);
        char data[8];
        check(recv(probe, data, sizeof(data), 0) == 3 && !atomic_load(&receiver.done),
              "restarted UDP receive waits on replacement description");
        unsigned char payload[31];
        for (unsigned i = 0; i < sizeof(payload); i++)
            payload[i] = (unsigned char)(i * 13 + 7);
        check(sendto(sender, payload, sizeof(payload), 0, (struct sockaddr*)&replacement_local,
                     sizeof(replacement_local)) == sizeof(payload),
              "UDP replacement port completes restarted request");
        check(pthread_join(thread, NULL) == 0 && receiver.result == sizeof(payload) &&
                  !memcmp(receiver.bytes, payload, sizeof(payload)),
              "UDP restarted syscall performs fresh descriptor lookup");
    } else
        check(pthread_join(thread, NULL) == 0 && receiver.result == -1 && receiver.error == EINTR,
              "UDP caught signal returns EINTR");
    close(probe);
    close(replacement);
    close(sender);
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    check(sigaction(SIGUSR1, &action, NULL) == 0, "UDP interruption handler restore");
    puts(restart ? "UDP_RESTART_PASS" : "UDP_INTERRUPT_PASS");
}

static void fork_lifetime(void) {
    struct sockaddr_in local;
    int server = endpoint(0x7f000001, &local), control[2];
    check(pipe(control) == 0, "UDP fork control pipe");
    fflush(stdout);
    pid_t child = fork();
    check(child >= 0, "UDP fork");
    if (!child) {
        close(control[1]);
        char byte;
        check(read(control[0], &byte, 1) == 1, "UDP fork start");
        readable(server);
        struct sockaddr_in source;
        socklen_t size = sizeof(source);
        unsigned char data[16];
        check(recvfrom(server, data, sizeof(data), 0, (struct sockaddr*)&source, &size) == 8 &&
                  !memcmp(data, "inherited", 8),
              "UDP inherited server receives after parent closes");
        check(sendto(server, data, 8, 0, (struct sockaddr*)&source, sizeof(source)) == 8,
              "UDP inherited server replies");
        close(server);
        close(control[0]);
        _exit(0);
    }
    close(control[0]);
    check(close(server) == 0, "UDP parent releases forked descriptor");
    int probe = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    check(probe >= 0 && bind(probe, (struct sockaddr*)&local, sizeof(local)) == -1 &&
              errno == EADDRINUSE,
          "UDP inherited description retains bound port");
    struct sockaddr_in source;
    int sender = endpoint(0x7f000001, &source);
    check(write(control[1], "x", 1) == 1 &&
              sendto(sender, "inherited", 8, 0, (struct sockaddr*)&local, sizeof(local)) == 8,
          "UDP forked server wake and input");
    readable(sender);
    char data[16];
    socklen_t size = sizeof(source);
    check(recvfrom(sender, data, sizeof(data), 0, (struct sockaddr*)&source, &size) == 8 &&
              !memcmp(data, "inherited", 8) && source.sin_port == local.sin_port,
          "UDP forked server source port and bytes");
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
              bind(probe, (struct sockaddr*)&local, sizeof(local)) == 0,
          "UDP forked process final close releases port");
    close(sender);
    close(probe);
    close(control[1]);
    puts("UDP_FORK_PASS");
}

static void resource_cycles(void) {
    for (unsigned sequence = 0; sequence < 128; sequence++) {
        struct sockaddr_in local;
        int fd = endpoint(0x7f000001, &local);
        unsigned char expected = sequence, actual = 0;
        check(sendto(fd, &expected, 1, 0, (struct sockaddr*)&local, sizeof(local)) == 1,
              "UDP repeated endpoint output");
        readable(fd);
        check(recv(fd, &actual, 1, 0) == 1 && actual == expected && close(fd) == 0,
              "UDP repeated endpoint receive and teardown");
    }
    puts("UDP_RESOURCE_CYCLES_PASS count=128");
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "UDP interface control descriptor");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        struct sockaddr_in value = address(0, 0x0a170102 + (lane << 8));
        memcpy(&request.ifr_addr, &value, sizeof(value));
        check(ioctl(fd, SIOCSIFADDR, &request) == 0, "UDP static interface address");
        value.sin_addr.s_addr = htonl(0xffffff00);
        memcpy(&request.ifr_netmask, &value, sizeof(value));
        check(ioctl(fd, SIOCSIFNETMASK, &request) == 0, "UDP static interface mask");
        check(ioctl(fd, SIOCGIFFLAGS, &request) == 0, "UDP interface flags query");
        request.ifr_flags |= IFF_UP;
        check(ioctl(fd, SIOCSIFFLAGS, &request) == 0, "UDP interface up");
    }
    close(fd);
    puts("UDP_CONFIG_PASS");
}

static void payload_bytes(unsigned char* data, size_t length, unsigned lane, unsigned phase,
                          unsigned sequence) {
    check(length >= 8, "UDP test payload size");
    data[0] = 'U';
    data[1] = 'D';
    data[2] = phase;
    data[3] = lane;
    data[4] = sequence >> 8;
    data[5] = sequence;
    data[6] = length >> 8;
    data[7] = length;
    for (unsigned i = 8; i < length; i++)
        data[i] = (unsigned char)(i * 17 + sequence * 13 + lane * 7);
}

static int wire_endpoint(unsigned lane, unsigned port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    check(fd >= 0, "UDP wire socket");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "UDP wire interface binding");
    struct sockaddr_in local = address(port, 0x0a170102 + (lane << 8));
    check(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0, "UDP wire local binding");
    return fd;
}

static void wire_send(int fd, unsigned lane, unsigned phase, unsigned sequence, size_t length) {
    unsigned char data[1500];
    check(length <= sizeof(data), "UDP wire fixture size");
    payload_bytes(data, length, lane, phase, sequence);
    check(send(fd, data, length, 0) == (ssize_t)length, "UDP connected wire send");
}

static void wire_receive(int fd, unsigned lane, unsigned phase, unsigned sequence, size_t length) {
    unsigned char expected[1500], actual[1500];
    payload_bytes(expected, length, lane, phase, sequence);
    readable(fd);
    struct sockaddr_in source;
    socklen_t size = sizeof(source);
    check(recvfrom(fd, actual, sizeof(actual), 0, (struct sockaddr*)&source, &size) ==
                  (ssize_t)length &&
              !memcmp(actual, expected, length) && size == sizeof(source) &&
              source.sin_family == AF_INET && source.sin_port == htons(9000) &&
              source.sin_addr.s_addr == htonl(0x0a170101 + (lane << 8)),
          "UDP host payload and source metadata");
}

static unsigned checksum_bytes(const unsigned char* data, size_t length) {
    unsigned sum = 0;
    while (length >= 2) {
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

static void zero_checksum(int fd, unsigned lane) {
    unsigned char pseudo[20] = {10, 23, lane + 1, 2, 10, 23, lane + 1, 1, 0, 17, 0, 10};
    unsigned port = 41000 + lane;
    pseudo[12] = port >> 8;
    pseudo[13] = port;
    pseudo[14] = 9001 >> 8;
    pseudo[15] = 9001 & 255;
    pseudo[17] = 10;
    unsigned sum = checksum_bytes(pseudo, sizeof(pseudo));
    unsigned char data[2] = {sum >> 8, sum}, actual[2];
    struct sockaddr_in peer = address(9001, 0x0a170101 + (lane << 8));
    check(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0 && send(fd, data, 2, 0) == 2,
          "UDP computed-zero checksum send");
    readable(fd);
    check(recv(fd, actual, sizeof(actual), 0) == 2 && !memcmp(actual, data, 2),
          "UDP computed-zero checksum reply");
    peer.sin_port = htons(9000);
    check(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0,
          "UDP restore peer after zero checksum");
    printf("UDP_ZERO_CHECKSUM_PASS index=%u\n", lane + 1);
}

static int packet_listener(unsigned lane) {
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(0x0800));
    check(fd >= 0, "UDP ingress observer");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    struct sockaddr_ll local = {.sll_family = AF_PACKET,
                                .sll_protocol = htons(0x0800),
                                .sll_ifindex = if_nametoindex(name)};
    int value = 1;
    check(local.sll_ifindex > 0 && bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0 &&
              setsockopt(fd, 263, 23, &value, 4) == 0,
          "UDP ingress observer interface and outgoing suppression");
    return fd;
}

static void ingress(int fd, unsigned count, unsigned first) {
    unsigned seen = 0;
    for (unsigned i = 0; i < count; i++) {
        unsigned char frame[2048];
        readable(fd);
        ssize_t length = recv(fd, frame, sizeof(frame), 0);
        check(length >= 34 && frame[12] == 8 && frame[13] == 0, "UDP ingress captured IPv4 frame");
        unsigned identifier = ((unsigned)frame[18] << 8) | frame[19];
        check(identifier >= first && identifier < first + count &&
                  !(seen & (1u << (identifier - first))),
              "UDP ingress all distinct fixture packets");
        seen |= 1u << (identifier - first);
    }
    check(seen == (1u << count) - 1, "UDP ingress complete fixture set");
    empty(fd);
    close(fd);
}

static void malformed(int fd, unsigned lane) {
    int listener = packet_listener(lane);
    wire_send(fd, lane, 'V', 0, 31);
    wire_receive(fd, lane, 'V', 0, 31);
    ingress(listener, 15, 0x7000);
    empty(fd);
    printf("UDP_MALFORMED_PASS index=%u frames=15\n", lane + 1);
    listener = packet_listener(lane);
    wire_send(fd, lane, 'F', 0, 31);
    wire_receive(fd, lane, 'F', 0, 31);
    ingress(listener, 3, 0x7100);
    empty(fd);
    printf("UDP_CONNECTED_FILTER_PASS index=%u\n", lane + 1);
}

static void server_exchange(int control, unsigned lane) {
    int server = wire_endpoint(lane, 42000 + lane);
    wire_send(control, lane, 'S', 0, 31);
    readable(server);
    unsigned char expected[73], actual[100];
    payload_bytes(expected, sizeof(expected), lane, 'Q', 0);
    struct sockaddr_in source;
    socklen_t size = sizeof(source);
    check(recvfrom(server, actual, sizeof(actual), 0, (struct sockaddr*)&source, &size) == 73 &&
              !memcmp(actual, expected, sizeof(expected)) && size == sizeof(source) &&
              source.sin_family == AF_INET && source.sin_port == htons(9002) &&
              source.sin_addr.s_addr == htonl(0x0a170101 + (lane << 8)),
          "UDP host initiated server request");
    check(sendto(server, actual, 73, 0, (struct sockaddr*)&source, sizeof(source)) == 73,
          "UDP guest server response");
    wire_receive(control, lane, 'S', 0, 31);
    wire_send(control, lane, 'O', 0, 31);
    const unsigned order[4] = {2, 0, 2, 1};
    for (unsigned i = 0; i < 4; i++) {
        readable(server);
        size = sizeof(source);
        check(recvfrom(server, actual, sizeof(actual), 0, (struct sockaddr*)&source, &size) == 31,
              "UDP reordered server input");
        payload_bytes(expected, 31, lane, 'O', order[i]);
        check(!memcmp(actual, expected, 31) && source.sin_port == htons(9004),
              "UDP preserves input duplication and order");
        check(sendto(server, actual, 31, 0, (struct sockaddr*)&source, sizeof(source)) == 31,
              "UDP reordered server response");
    }
    wire_receive(control, lane, 'O', 0, 31);
    empty(server);
    close(server);
    printf("UDP_SERVER_PASS index=%u\n", lane + 1);
}

static void wire_errors(int fd, unsigned lane) {
    // Separate this valid closed-port request from the earlier filtered tuple's
    // bounded ICMP response interval.
    struct timespec delay = {.tv_sec = 1, .tv_nsec = 100000000};
    nanosleep(&delay, NULL);
    wire_send(fd, lane, 'C', 0, 31);
    wire_receive(fd, lane, 'C', 0, 31);
    wire_send(fd, lane, 'I', 0, 31);
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 2000) == 1 && (poller.revents & POLLERR) && !(poller.revents & POLLIN),
          "UDP quoted connected error readiness");
    socklen_t size = sizeof(int);
    check(syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR, (void*)1, &size) == -1 &&
              errno == EFAULT,
          "UDP SO_ERROR failed copy");
    int error = 0;
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == EMSGSIZE,
          "UDP valid quoted tuple error retained through failed copy");
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0 &&
              poll(&poller, 1, 0) == 0,
          "UDP quoted error clear removes readiness");
    printf("UDP_WIRE_ERRORS_PASS index=%u\n", lane + 1);
}

static int group_endpoint(unsigned lane) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0), value = 1;
    check(fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &value, 4) == 0,
          "UDP broadcast reusable endpoint");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
          "UDP broadcast interface");
    struct sockaddr_in local = address(44000 + lane, 0);
    check(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0, "UDP broadcast wildcard port");
    return fd;
}

static void group_send(int fd, unsigned lane, unsigned sequence) {
    struct sockaddr_in target = address(9000, 0xffffffff);
    unsigned char data[31];
    payload_bytes(data, sizeof(data), lane, 'B', sequence);
    check(sendto(fd, data, sizeof(data), 0, (struct sockaddr*)&target, sizeof(target)) ==
              sizeof(data),
          "UDP broadcast wire send");
}

struct GroupReader {
    int fd;
    unsigned lane;
    atomic_int started;
};

static void* group_reader(void* pointer) {
    struct GroupReader* reader = pointer;
    atomic_store(&reader->started, 1);
    struct sockaddr_in target = address(9003, 0x0a170101 + (reader->lane << 8));
    for (unsigned sequence = 0; sequence < 48; sequence++) {
        wire_receive(reader->fd, reader->lane, 'K', sequence, 31);
        unsigned char data[31];
        payload_bytes(data, sizeof(data), reader->lane, 'K', sequence);
        check(sendto(reader->fd, data, sizeof(data), 0, (struct sockaddr*)&target,
                     sizeof(target)) == sizeof(data),
              "UDP active broadcast receiver acknowledges each ingress");
    }
    return NULL;
}

static void broadcast(int fd, unsigned lane) {
    int slow = group_endpoint(lane), active = group_endpoint(lane), value = 1;
    struct sockaddr_in target = address(9000, 0xffffffff);
    unsigned char data[31];
    payload_bytes(data, sizeof(data), lane, 'B', 0);
    check(sendto(fd, data, sizeof(data), 0, (struct sockaddr*)&target, sizeof(target)) == -1 &&
              errno == EACCES,
          "UDP broadcast requires permission option");
    check(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &value, 4) == 0, "UDP broadcast permission");
    group_send(fd, lane, 0);
    wire_receive(slow, lane, 'B', 0, 31);
    wire_receive(active, lane, 'B', 0, 31);
    empty(slow);
    empty(active);
    value = 1024;
    check(setsockopt(slow, SOL_SOCKET, SO_RCVBUF, &value, 4) == 0,
          "UDP bounded broadcast receive buffer");
    group_send(fd, lane, 1);
    wire_receive(slow, lane, 'B', 1, 1400);
    wire_receive(active, lane, 'B', 1, 1400);
    wire_receive(active, lane, 'B', 2, 1400);
    empty(slow);
    empty(active);
    value = 32768;
    check(setsockopt(slow, SOL_SOCKET, SO_RCVBUF, &value, 4) == 0,
          "restore UDP bounded receive buffer");
    struct GroupReader reader = {.fd = active, .lane = lane};
    pthread_t thread;
    check(pthread_create(&thread, NULL, group_reader, &reader) == 0, "UDP active broadcast reader");
    while (!atomic_load(&reader.started))
        usleep(1000);
    group_send(fd, lane, 2);
    check(pthread_join(thread, NULL) == 0, "UDP active receiver accepts all 48 datagrams");
    for (unsigned sequence = 0; sequence < 32; sequence++)
        wire_receive(slow, lane, 'K', sequence, 31);
    empty(slow);
    empty(active);
    close(active);
    close(slow);
    printf("UDP_BROADCAST_QUEUE_PASS index=%u ingress=48 retained=32\n", lane + 1);
}

static void wait_link(int fd, const char* name, int up) {
    for (unsigned attempt = 0; attempt < 3000; attempt++) {
        struct ifreq request = {0};
        strcpy(request.ifr_name, name);
        check(ioctl(fd, SIOCGIFFLAGS, &request) == 0, "UDP link flags");
        if (((request.ifr_flags & IFF_RUNNING) != 0) == up)
            return;
        usleep(1000);
    }
    check(0, "UDP link transition deadline");
}

static void link_change(int fd, unsigned lane) {
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    printf("UDP_LINK_DOWN index=%u\n", lane + 1);
    fflush(stdout);
    wait_link(fd, name, 0);
    unsigned char data[31];
    payload_bytes(data, sizeof(data), lane, 'L', 0);
    check(send(fd, data, sizeof(data), 0) == -1 && errno == ENETDOWN,
          "UDP carrier loss prevents output");
    struct sockaddr_in local;
    int loop = endpoint(0x7f000001, &local);
    check(sendto(loop, "loop", 4, 0, (struct sockaddr*)&local, sizeof(local)) == 4,
          "UDP loopback output during carrier loss");
    readable(loop);
    check(recv(loop, data, sizeof(data), 0) == 4 && !memcmp(data, "loop", 4),
          "UDP loopback input during carrier loss");
    close(loop);
    printf("UDP_LINK_UP index=%u\n", lane + 1);
    fflush(stdout);
    wait_link(fd, name, 1);
    wire_send(fd, lane, 'L', 0, 31);
    wire_receive(fd, lane, 'L', 0, 31);
    struct ifreq request = {0};
    strcpy(request.ifr_name, name);
    check(ioctl(fd, SIOCGIFFLAGS, &request) == 0, "UDP administrative flags");
    request.ifr_flags &= ~IFF_UP;
    check(ioctl(fd, SIOCSIFFLAGS, &request) == 0 && ioctl(fd, SIOCGIFFLAGS, &request) == 0 &&
              (request.ifr_flags & IFF_RUNNING),
          "UDP admin down preserves carrier");
    check(send(fd, data, sizeof(data), 0) == -1 && errno == ENETDOWN,
          "UDP admin down prevents output");
    request.ifr_flags |= IFF_UP;
    check(ioctl(fd, SIOCSIFFLAGS, &request) == 0, "UDP administrative restore");
    wire_send(fd, lane, 'R', 0, 31);
    wire_receive(fd, lane, 'R', 0, 31);
    printf("UDP_LINK_PASS index=%u\n", lane + 1);
}

struct Sender {
    int fd;
    atomic_int started, done;
    ssize_t result;
    unsigned char bytes[129], poison[129];
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

static void pressure(int control, unsigned lane) {
    int fd = wire_endpoint(lane, 45000 + lane);
    struct sockaddr_in destination = address(9000, 0x0a170103 + (lane << 8));
    unsigned char data[129];
    for (unsigned sequence = 0; sequence < 32; sequence++) {
        payload_bytes(data, sizeof(data), lane, 'P', sequence);
        check(sendto(fd, data, sizeof(data), 0, (struct sockaddr*)&destination,
                     sizeof(destination)) == sizeof(data),
              "UDP fills 32 pending IPv4 outputs");
    }
    payload_bytes(data, sizeof(data), lane, 'P', 32);
    check(sendto(fd, data, sizeof(data), 0, (struct sockaddr*)&destination, sizeof(destination)) ==
                  -1 &&
              errno == EAGAIN,
          "UDP bounded pending output returns EAGAIN");
    struct pollfd poller = {.fd = fd, .events = POLLOUT};
    check(poll(&poller, 1, 0) == 0, "full UDP output suppresses writable readiness");
    int observer = dup(fd), epoll = epoll_create1(EPOLL_CLOEXEC);
    check(observer >= 0 && epoll >= 0, "UDP pressure observer and epoll");
    struct epoll_event event = {.events = EPOLLOUT | EPOLLET, .data.u64 = 1};
    check(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event) == 0, "UDP reused descriptor epoll");
    event.data.u64 = 2;
    check(epoll_ctl(epoll, EPOLL_CTL_ADD, observer, &event) == 0 &&
              epoll_wait(epoll, &event, 1, 0) == 0,
          "UDP live observer epoll waits for capacity");
    check(fcntl(fd, F_SETFL, 0) == 0, "blocking UDP pending sender");
    struct Sender sender = {.fd = fd, .destination = destination};
    payload_bytes(sender.bytes, sizeof(sender.bytes), lane, 'P', 32);
    sender.vectors[0] = (struct iovec){sender.bytes, 11};
    sender.vectors[1] = (struct iovec){sender.bytes + 11, sizeof(sender.bytes) - 11};
    sender.message = (struct msghdr){.msg_name = &sender.destination,
                                     .msg_namelen = sizeof(sender.destination),
                                     .msg_iov = sender.vectors,
                                     .msg_iovlen = 2};
    pthread_t thread;
    check(pthread_create(&thread, NULL, blocked_sender, &sender) == 0, "UDP blocked sender thread");
    while (!atomic_load(&sender.started))
        usleep(1000);
    usleep(50000);
    check(!atomic_load(&sender.done), "UDP 33rd sender actually blocks");
    check(close(fd) == 0, "close original blocked UDP sender descriptor");
    int replacement = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    check(replacement >= 0, "UDP replacement sender socket");
    if (replacement != fd) {
        check(dup2(replacement, fd) == fd && close(replacement) == 0,
              "reuse original UDP sender descriptor");
        replacement = fd;
    }
    memset(sender.bytes, 0xa5, sizeof(sender.bytes));
    memset(sender.poison, 0xa5, sizeof(sender.poison));
    sender.destination = address(9999, 0x0a170104 + (lane << 8));
    sender.vectors[0] = (struct iovec){sender.poison, 0};
    sender.vectors[1] = (struct iovec){sender.poison, 0};
    sender.message.msg_name = sender.poison;
    sender.message.msg_namelen = 0;
    sender.message.msg_iov = NULL;
    sender.message.msg_iovlen = 0;
    printf("UDP_PRESSURE_RELEASE index=%u\n", lane + 1);
    fflush(stdout);
    check(pthread_join(thread, NULL) == 0 && sender.result == sizeof(sender.bytes),
          "UDP retained send description, original destination port and bytes");
    check(epoll_wait(epoll, &event, 1, 2000) == 1 && event.data.u64 == 2 &&
              (event.events & EPOLLOUT) && epoll_wait(epoll, &event, 1, 0) == 0,
          "UDP capacity wakes retained observer and excludes reused descriptor");
    struct sockaddr_in local = address(45000 + lane, 0x0a170102 + (lane << 8));
    check(bind(replacement, (struct sockaddr*)&local, sizeof(local)) == -1 && errno == EADDRINUSE &&
              close(observer) == 0 &&
              bind(replacement, (struct sockaddr*)&local, sizeof(local)) == 0,
          "UDP pending sender port remains until final owner closes");
    empty(replacement);
    close(replacement);
    close(epoll);
    wire_receive(control, lane, 'P', 33, 31);
    printf("UDP_PRESSURE_PASS index=%u packets=33\n", lane + 1);
}

static void unreachable(unsigned lane) {
    int fd = wire_endpoint(lane, 46000 + lane);
    struct sockaddr_in peer = address(9000, 0x0a170163 + (lane << 8));
    check(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0, "UDP unresolved connected peer");
    wire_send(fd, lane, 'U', 0, 31);
    struct pollfd poller = {.fd = fd, .events = POLLIN};
    check(poll(&poller, 1, 4500) == 1 && (poller.revents & POLLERR),
          "UDP unanswered ARP reaches bounded socket error");
    socklen_t size = sizeof(int);
    check(syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR, (void*)1, &size) == -1 &&
              errno == EFAULT,
          "UDP unreachable error failed copy");
    int error;
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == EHOSTUNREACH &&
              getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0,
          "UDP unanswered ARP error retained and cleared");
    close(fd);
    printf("UDP_UNREACHABLE_PASS index=%u\n", lane + 1);
}

static void wire(unsigned lane) {
    int fd = wire_endpoint(lane, 41000 + lane);
    struct sockaddr_in peer = address(9000, 0x0a170101 + (lane << 8));
    unsigned char data[1500], actual[1500];
    payload_bytes(data, 129, lane, 'E', 0);
    check(sendto(fd, data, 129, 0, (struct sockaddr*)&peer, sizeof(peer)) == 129,
          "UDP named wire send");
    wire_receive(fd, lane, 'E', 0, 129);
    check(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0, "UDP wire connected peer");
    payload_bytes(data, 47, lane, 'E', 1);
    struct iovec vectors[2] = {{data, 7}, {data + 7, 40}};
    check(writev(fd, vectors, 2) == 47, "UDP wire gathered write");
    readable(fd);
    vectors[0] = (struct iovec){actual, 13};
    vectors[1] = (struct iovec){actual + 13, 34};
    check(readv(fd, vectors, 2) == 47 && !memcmp(actual, data, 47), "UDP wire scattered read");
    peer.sin_family = AF_UNSPEC;
    payload_bytes(data, 31, lane, 'E', 2);
    vectors[0] = (struct iovec){data, 11};
    vectors[1] = (struct iovec){data + 11, 20};
    struct msghdr message = {
        .msg_name = &peer, .msg_namelen = sizeof(peer), .msg_iov = vectors, .msg_iovlen = 2};
    check(sendmsg(fd, &message, 0) == 31, "UDP AF_UNSPEC named sendmsg");
    wire_receive(fd, lane, 'E', 2, 31);
    peer.sin_family = AF_INET;
    peer.sin_port = 0;
    check(sendto(fd, data, 31, 0, (struct sockaddr*)&peer, sizeof(peer)) == -1 && errno == EINVAL,
          "UDP named zero destination port rejected");
    check(send(fd, data, 1473, 0) == -1 && errno == EMSGSIZE,
          "UDP payload includes IPv4 and UDP overhead in MTU");
    wire_send(fd, lane, 'M', 0, 1472);
    wire_receive(fd, lane, 'M', 0, 1472);
    check(send(fd, NULL, 0, 0) == 0, "UDP wire zero payload send");
    readable(fd);
    check(recv(fd, NULL, 0, 0) == 0, "UDP wire zero payload receive");
    empty(fd);
    zero_checksum(fd, lane);
    malformed(fd, lane);
    server_exchange(fd, lane);
    wire_errors(fd, lane);
    broadcast(fd, lane);
    pressure(fd, lane);
    unreachable(lane);
    link_change(fd, lane);
    close(fd);
    printf("UDP_WIRE_PASS index=%u\n", lane + 1);
}

static void device_fault(void) {
    int fd = wire_endpoint(0, 47000);
    struct sockaddr_in peer = address(9000, 0x0a170101);
    check(connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0, "UDP fault connected interface");
    puts("UDP_FAULT_READY");
    fflush(stdout);
    wire_send(fd, 0, 'G', 0, 31);
    struct pollfd poller = {.fd = fd, .events = POLLIN | POLLOUT};
    for (unsigned attempt = 0; attempt < 3000; attempt++) {
        check(poll(&poller, 1, 0) >= 0, "UDP fault poll");
        if (poller.revents & POLLERR)
            break;
        usleep(1000);
    }
    check((poller.revents & POLLERR) && !(poller.revents & POLLIN),
          "UDP failed bound interface error readiness");
    unsigned char data[31];
    check(recv(fd, data, sizeof(data), 0) == -1 && errno == EIO &&
              send(fd, data, sizeof(data), 0) == -1 && errno == EIO,
          "UDP failed bound interface data returns EIO");
    int error = 0;
    socklen_t size = sizeof(error);
    check(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == EIO &&
              getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == EIO,
          "UDP failed interface error remains persistent");
    close(fd);
    puts("UDP_DEVICE_FAULT_PASS");
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in local = address(47001, 0);
    peer = address(9000, 0x0a170201);
    check(fd >= 0 && bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0 &&
              connect(fd, (struct sockaddr*)&peer, sizeof(peer)) == 0,
          "UDP unbound-device socket selects remaining interface");
    wire_send(fd, 1, 'G', 0, 31);
    wire_receive(fd, 1, 'G', 0, 31);
    close(fd);
    puts("UDP_OTHER_NIC_PASS");
}

static void loopback(void) {
    struct sockaddr_in local, peer, source;
    int server = endpoint(0x7f000001, &local);
    int client = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    check(client >= 0, "UDP explicit protocol");
    unsigned char payload[23], buffer[64];
    for (unsigned i = 0; i < sizeof(payload); i++)
        payload[i] = (unsigned char)(i * 17 + 9);
    check(sendto(client, payload, sizeof(payload), 0, (struct sockaddr*)&local, sizeof(local)) ==
              sizeof(payload),
          "UDP named odd payload");
    readable(server);
    socklen_t size = sizeof(peer);
    check(getsockname(client, (struct sockaddr*)&peer, &size) == 0 && peer.sin_port != 0 &&
              peer.sin_addr.s_addr == 0,
          "UDP named send autobinds wildcard");
    int available = 0;
    check(ioctl(server, FIONREAD, &available) == 0 && available == sizeof(payload),
          "UDP FIONREAD payload length");
    check(read(server, buffer, 0) == 0 && readv(server, NULL, 0) == 0 &&
              ioctl(server, FIONREAD, &available) == 0 && available == sizeof(payload),
          "zero descriptor reads retain UDP");
    check(recv(server, buffer, 5, MSG_PEEK | MSG_TRUNC) == sizeof(payload) &&
              !memcmp(buffer, payload, 5),
          "UDP peek original length");
    struct iovec vectors[2] = {{buffer, 3}, {buffer + 3, 4}};
    struct msghdr message = {
        .msg_name = &source, .msg_namelen = sizeof(source), .msg_iov = vectors, .msg_iovlen = 2};
    check(recvmsg(server, &message, MSG_PEEK) == 7 && (message.msg_flags & MSG_TRUNC) &&
              message.msg_namelen == sizeof(source) && message.msg_controllen == 0 &&
              source.sin_family == AF_INET && source.sin_port == peer.sin_port &&
              source.sin_addr.s_addr == htonl(0x7f000001) && !memcmp(buffer, payload, 7),
          "UDP scatter truncation and source port");
    vectors[0] = (struct iovec){(void*)1, sizeof(buffer)};
    message = (struct msghdr){.msg_iov = vectors, .msg_iovlen = 1};
    check(recvmsg(server, &message, MSG_PEEK) == -1 && errno == EFAULT &&
              ioctl(server, FIONREAD, &available) == 0 && available == sizeof(payload),
          "UDP failed peek retains datagram");
    check(recvmsg(server, &message, 0) == -1 && errno == EFAULT &&
              ioctl(server, FIONREAD, &available) == 0 && available == 0,
          "UDP nonpeek copy fault consumes datagram");
    empty(server);
    check(connect(client, (struct sockaddr*)&local, sizeof(local)) == 0,
          "UDP connect after named send");
    size = sizeof(peer);
    check(getpeername(client, (struct sockaddr*)&peer, &size) == 0 &&
              peer.sin_port == local.sin_port && peer.sin_addr.s_addr == local.sin_addr.s_addr,
          "UDP connected peer name");
    vectors[0] = (struct iovec){payload, 7};
    vectors[1] = (struct iovec){payload + 7, sizeof(payload) - 7};
    message = (struct msghdr){.msg_iov = vectors, .msg_iovlen = 2};
    check(sendmsg(client, &message, 0) == sizeof(payload), "UDP connected gathered send");
    readable(server);
    size = sizeof(source);
    check(recvfrom(server, buffer, sizeof(buffer), 0, (struct sockaddr*)&source, &size) ==
                  sizeof(payload) &&
              !memcmp(buffer, payload, sizeof(payload)),
          "UDP payload-only receive");
    check(sendto(server, payload, sizeof(payload), 0, (struct sockaddr*)&source, sizeof(source)) ==
              sizeof(payload),
          "UDP server reply");
    readable(client);
    check(read(client, buffer, sizeof(buffer)) == sizeof(payload) &&
              !memcmp(buffer, payload, sizeof(payload)),
          "UDP connected descriptor read");
    check(send(client, payload, sizeof(payload), 0) == sizeof(payload),
          "UDP payload for zero-size socket receive");
    readable(server);
    check(recv(server, NULL, 0, 0) == 0, "zero-size socket receive consumes UDP payload");
    empty(server);
    check(send(client, payload, sizeof(payload), 0) == sizeof(payload),
          "UDP payload for zero-size truncated receive");
    readable(server);
    check(recv(server, NULL, 0, MSG_TRUNC) == sizeof(payload),
          "zero-size truncated receive reports original UDP length");
    empty(server);
    check(write(client, NULL, 0) == 0, "UDP zero payload send");
    readable(server);
    check(ioctl(server, FIONREAD, &available) == 0 && available == 0,
          "zero UDP payload has readable packet and zero FIONREAD");
    size = sizeof(source);
    check(recvfrom(server, NULL, 0, 0, (struct sockaddr*)&source, &size) == 0 &&
              source.sin_port != 0,
          "zero UDP payload receive metadata");
    empty(server);
    struct sockaddr disconnect = {.sa_family = AF_UNSPEC};
    check(connect(client, &disconnect, sizeof(disconnect)) == 0, "UDP disconnect");
    size = sizeof(peer);
    check(getsockname(client, (struct sockaddr*)&peer, &size) == 0 && peer.sin_port == 0 &&
              peer.sin_addr.s_addr == 0,
          "UDP disconnect releases automatic binding");
    check(send(client, payload, 1, 0) == -1 && errno == EDESTADDRREQ,
          "unconnected UDP requires destination");
    close(client);
    close(server);
    puts("UDP_LOOPBACK_PASS");
}

static void payload_limits(void) {
    struct sockaddr_in local;
    int receiver = endpoint(0x7f000001, &local);
    int sender = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    unsigned char* expected = malloc(65508);
    unsigned char* actual = malloc(65507);
    check(sender >= 0 && expected && actual, "UDP maximum payload buffers");
    for (unsigned i = 0; i < 65508; i++)
        expected[i] = (unsigned char)(i * 13 + 7);
    check(sendto(sender, expected, 65508, 0, (struct sockaddr*)&local, sizeof(local)) == -1 &&
              errno == EMSGSIZE,
          "UDP payload above IPv4 maximum rejected");
    check(sendto(sender, expected, 65507, 0, (struct sockaddr*)&local, sizeof(local)) == 65507,
          "UDP maximum odd payload accepted on loopback");
    readable(receiver);
    int available = 0;
    check(ioctl(receiver, FIONREAD, &available) == 0 && available == 65507 &&
              recv(receiver, actual, 65507, 0) == 65507 && !memcmp(actual, expected, 65507),
          "UDP maximum length, checksum, and payload preserved");
    empty(receiver);
    close(sender);
    close(receiver);
    free(actual);
    free(expected);
    puts("UDP_PAYLOAD_LIMIT_PASS bytes=65507");
}

static void buffer_limits(void) {
    struct sockaddr_in local;
    int receiver = endpoint(0x7f000001, &local);
    int sender = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int value = 1024;
    socklen_t size = sizeof(value);
    unsigned char payload[2021], actual[2020];
    memset(payload, 0x37, sizeof(payload));
    check(sender >= 0 && setsockopt(sender, SOL_SOCKET, SO_SNDBUF, &value, size) == 0 &&
              getsockopt(sender, SOL_SOCKET, SO_SNDBUF, &value, &size) == 0 && value == 2048,
          "UDP bounded send buffer reports 2048 bytes");
    check(sendto(sender, payload, sizeof(payload), 0, (struct sockaddr*)&local, sizeof(local)) ==
                  -1 &&
              errno == EMSGSIZE,
          "UDP send quota includes 28 header bytes");
    check(sendto(sender, payload, sizeof(actual), 0, (struct sockaddr*)&local, sizeof(local)) ==
              sizeof(actual),
          "UDP exact send quota accepted");
    readable(receiver);
    check(recv(receiver, actual, sizeof(actual), 0) == sizeof(actual) &&
              !memcmp(actual, payload, sizeof(actual)),
          "UDP exact send quota bytes preserved");
    empty(receiver);
    close(sender);
    close(receiver);
    puts("UDP_BUFFER_LIMIT_PASS bytes=2048 payload=2020");
}

int main(int argc, char** argv) {
    bindings();
    zero_peer();
    loopback();
    payload_limits();
    reuse();
    shutdowns();
    errors();
    receive_lifetime(0);
    interrupted(0);
    interrupted(1);
    fork_lifetime();
    resource_cycles();
    if (argc > 1 && !strcmp(argv[1], "--captured")) {
        receive_lifetime(1);
        buffer_limits();
    }
    if (argc > 1 && !strcmp(argv[1], "--wire")) {
        receive_lifetime(1);
        buffer_limits();
        configure();
        if (getenv("AXIOM64_UDP_FAULT"))
            device_fault();
        else {
            wire(0);
            wire(1);
        }
    }
    puts("UDP_TESTS_PASS");
    return 0;
}
