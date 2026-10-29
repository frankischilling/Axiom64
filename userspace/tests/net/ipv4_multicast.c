// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define GROUP 0xef6a4307U
#define PORT 46067
static unsigned indices[2];
static unsigned char macs[2][6];
static int controls[2];

static void check(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "MULTICAST_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

static struct sockaddr_in address(unsigned ip, unsigned port) {
    return (struct sockaddr_in){
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(ip)};
}

static void option(int fd, int name, int value) {
    check(!setsockopt(fd, IPPROTO_IP, name, &value, sizeof(value)), "scalar option");
    int actual = -123;
    socklen_t length = sizeof(actual);
    check(!getsockopt(fd, IPPROTO_IP, name, &actual, &length) && actual == value &&
              length == sizeof(actual),
          "scalar readback");
}

static int endpoint(unsigned port, unsigned group) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0), reuse = 1;
    struct sockaddr_in local = address(group, port);
    check(fd >= 0 && !setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) &&
              !bind(fd, (struct sockaddr*)&local, sizeof(local)),
          "reused endpoint");
    return fd;
}

static void membership(int fd, int action, unsigned lane) {
    struct ip_mreqn request = {.imr_multiaddr.s_addr = htonl(GROUP),
                               .imr_ifindex = (int)indices[lane]};
    check(!setsockopt(fd, IPPROTO_IP, action, &request, sizeof(request)), "membership change");
}

static void absent(int fd) {
    struct pollfd item = {.fd = fd, .events = POLLIN};
    check(poll(&item, 1, 150) == 0, "uninterested receiver quiet");
    char byte;
    check(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN, "uninterested receiver empty");
}

static void received(int fd, const unsigned char* expected, size_t length, unsigned source) {
    struct pollfd item = {.fd = fd, .events = POLLIN};
    check(poll(&item, 1, 2000) == 1 && item.revents == POLLIN, "interested receiver readiness");
    unsigned char bytes[64];
    struct sockaddr_in peer;
    socklen_t size = sizeof(peer);
    check(recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&peer, &size) ==
                  (ssize_t)length &&
              !memcmp(bytes, expected, length) && size == sizeof(peer) &&
              peer.sin_family == AF_INET && peer.sin_addr.s_addr == htonl(source),
          "actual multicast datagram and peer");
}

static void control(unsigned lane, unsigned phase) {
    unsigned char frame[60] = {0};
    unsigned char peer[6] = {2, 0x41, 0x58, 0x4d, 0x43, (unsigned char)lane};
    memcpy(frame, peer, 6);
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = 0x88;
    frame[13] = 0xb9;
    memcpy(frame + 14, "AXMC", 4);
    frame[18] = lane;
    frame[19] = phase;
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(0x88b9),
                                 .sll_ifindex = (int)indices[lane],
                                 .sll_halen = 6};
    memcpy(target.sll_addr, peer, 6);
    check(sendto(controls[lane], frame, sizeof(frame), 0, (struct sockaddr*)&target,
                 sizeof(target)) == sizeof(frame),
          "physical control request");
    struct pollfd item = {.fd = controls[lane], .events = POLLIN};
    check(poll(&item, 1, 4000) == 1 && (item.revents & POLLIN), "physical peer acknowledgment");
    unsigned char reply[128];
    check(recv(controls[lane], reply, sizeof(reply), 0) == sizeof(frame) &&
              !memcmp(reply, macs[lane], 6) && !memcmp(reply + 6, peer, 6) && reply[12] == 0x88 &&
              reply[13] == 0xb9 && !memcmp(reply + 14, "AXMA", 4) && reply[18] == lane &&
              reply[19] == phase,
          "physical peer identity and phase");
}

static void ingress(unsigned lane, unsigned phase, int first, int second) {
    control(lane, phase);
    unsigned char payload[] = {'A', 'X', 'M', 'C', 'W', (unsigned char)lane, (unsigned char)phase};
    if (first >= 0)
        received(first, payload, sizeof(payload), 0x0a430101 + (lane << 8));
    if (second >= 0)
        received(second, payload, sizeof(payload), 0x0a430101 + (lane << 8));
    printf("MULTICAST_INGRESS lane=%u phase=%u receivers=%u\n", lane, phase,
           (first >= 0) + (second >= 0));
}

static void configure(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "interface control socket");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, IFNAMSIZ, "eth%u", lane);
        check(!ioctl(fd, SIOCGIFINDEX, &request), "interface index");
        indices[lane] = request.ifr_ifindex;
        check(!ioctl(fd, SIOCGIFHWADDR, &request), "interface hardware address");
        memcpy(macs[lane], request.ifr_hwaddr.sa_data, 6);
        struct sockaddr_in local = address(0x0a430102 + (lane << 8), 0);
        memcpy(&request.ifr_addr, &local, sizeof(local));
        check(!ioctl(fd, SIOCSIFADDR, &request), "interface address");
        local = address(0xffffff00, 0);
        memcpy(&request.ifr_netmask, &local, sizeof(local));
        check(!ioctl(fd, SIOCSIFNETMASK, &request), "interface netmask");
        request.ifr_flags = IFF_UP;
        check(!ioctl(fd, SIOCSIFFLAGS, &request), "interface administrative state");
        controls[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(0x88b9));
        struct sockaddr_ll link = {.sll_family = AF_PACKET,
                                   .sll_protocol = htons(0x88b9),
                                   .sll_ifindex = (int)indices[lane]};
        check(controls[lane] >= 0 && !bind(controls[lane], (struct sockaddr*)&link, sizeof(link)),
              "physical control binding");
    }
    close(fd);
}

static void abi(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "option endpoint");
    option(fd, IP_MULTICAST_TTL, 1);
    option(fd, IP_MULTICAST_LOOP, 1);
    option(fd, IP_MULTICAST_ALL, 1);
    unsigned char byte = 37;
    check(!setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &byte, 1), "single byte TTL");
    byte = 0;
    socklen_t length = 1;
    check(!getsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &byte, &length) && byte == 37 &&
              length == 1,
          "single byte TTL result");
    int value = 256;
    check(setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &value, 4) == -1 && errno == EINVAL,
          "TTL overflow");
    struct ip_mreqn request = {.imr_multiaddr.s_addr = htonl(GROUP),
                               .imr_ifindex = (int)indices[0]};
    check(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, 7) == -1 && errno == EINVAL,
          "short membership");
    check(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, NULL, 12) == -1 && errno == EFAULT,
          "inaccessible membership");
    check(setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &request, 12) == -1 &&
              errno == EADDRNOTAVAIL,
          "drop absent membership");
    request.imr_multiaddr.s_addr = htonl(0x0a010203);
    check(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, 12) == -1 && errno == EINVAL,
          "unicast membership");
    request.imr_multiaddr.s_addr = htonl(GROUP);
    request.imr_ifindex = 0x7fffffff;
    check(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, 12) == -1 && errno == ENODEV,
          "missing membership interface");
    close(fd);
    int stream = socket(AF_INET, SOCK_STREAM, 0);
    check(stream >= 0, "stream option endpoint");
    value = 1;
    check(setsockopt(stream, IPPROTO_IP, IP_MULTICAST_TTL, &value, 4) == -1 && errno == EINVAL,
          "stream multicast TTL rejected");
    struct in_addr automatic = {0};
    check(setsockopt(stream, IPPROTO_IP, IP_MULTICAST_IF, &automatic, sizeof(automatic)) == -1 &&
              errno == EINVAL,
          "stream multicast output rejected");
    option(stream, IP_MULTICAST_LOOP, 1);
    option(stream, IP_MULTICAST_ALL, 1);
    close(stream);
    puts("MULTICAST_ABI_PASS");
}

static void tcp_flags(int fd, const char* role, int loop, int all) {
    int actual_loop = -1, actual_all = -1;
    socklen_t length = sizeof(actual_loop);
    check(!getsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &actual_loop, &length) &&
              length == sizeof(actual_loop),
          "TCP multicast loop query");
    length = sizeof(actual_all);
    check(!getsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &actual_all, &length) &&
              length == sizeof(actual_all),
          "TCP multicast all query");
    printf("MULTICAST_TCP_FLAGS role=%s loop=%d all=%d\n", role, actual_loop, actual_all);
    check(actual_loop == loop && actual_all == all, "TCP inherited multicast flags");
}

static void tcp_inheritance(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    check(listener >= 0 && client >= 0, "TCP multicast inheritance endpoints");
    option(listener, IP_MULTICAST_LOOP, 0);
    option(listener, IP_MULTICAST_ALL, 0);
    struct sockaddr_in local = address(0x7f000001, 0);
    socklen_t length = sizeof(local);
    check(!bind(listener, (struct sockaddr*)&local, sizeof(local)) && !listen(listener, 2) &&
              !getsockname(listener, (struct sockaddr*)&local, &length) && length == sizeof(local),
          "TCP multicast listener");
    check(!connect(client, (struct sockaddr*)&local, sizeof(local)), "TCP multicast connect");
    struct pollfd pending = {.fd = listener, .events = POLLIN};
    check(poll(&pending, 1, 2000) == 1 && (pending.revents & POLLIN),
          "TCP child queued before listener mutation");
    option(listener, IP_MULTICAST_LOOP, 1);
    option(listener, IP_MULTICAST_ALL, 1);
    int accepted = accept(listener, NULL, NULL);
    check(accepted >= 0, "TCP multicast accepted child");
    tcp_flags(listener, "listener-after-queue", 1, 1);
    tcp_flags(client, "active-defaults", 1, 1);
    tcp_flags(accepted, "accepted-snapshot", 0, 0);
    option(accepted, IP_MULTICAST_LOOP, 1);
    option(accepted, IP_MULTICAST_ALL, 1);
    option(listener, IP_MULTICAST_LOOP, 0);
    option(listener, IP_MULTICAST_ALL, 0);
    tcp_flags(listener, "listener-independent", 0, 0);
    tcp_flags(accepted, "accepted-independent", 1, 1);
    check(!close(listener), "close listener before retained traffic");
    const char payload[] = "AXMC";
    char reply[sizeof(payload)] = {0};
    check(send(client, payload, sizeof(payload), 0) == sizeof(payload) &&
              recv(accepted, reply, sizeof(reply), MSG_WAITALL) == sizeof(payload) &&
              !memcmp(payload, reply, sizeof(payload)),
          "accepted TCP data after listener close");
    check(send(accepted, reply, sizeof(reply), 0) == sizeof(reply) &&
              recv(client, reply, sizeof(reply), MSG_WAITALL) == sizeof(payload) &&
              !memcmp(payload, reply, sizeof(payload)),
          "retained TCP echo after listener close");
    check(!close(client) && !close(accepted), "TCP multicast inheritance close");
    puts("MULTICAST_TCP_INHERIT_PASS");
}

static void lifetime(void) {
    int owner = endpoint(PORT, GROUP), observer = endpoint(PORT, 0);
    membership(owner, IP_ADD_MEMBERSHIP, 0);
    struct ip_mreqn request = {.imr_multiaddr.s_addr = htonl(GROUP),
                               .imr_ifindex = (int)indices[0]};
    check(setsockopt(owner, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, sizeof(request)) == -1 &&
              errno == EADDRINUSE,
          "duplicate membership");
    option(observer, IP_MULTICAST_ALL, 0);
    ingress(0, 1, owner, -1);
    absent(observer);
    option(observer, IP_MULTICAST_ALL, 1);
    ingress(0, 2, owner, observer);
    option(observer, IP_MULTICAST_ALL, 0);
    int retained = dup(owner);
    check(retained >= 0 && !close(owner), "duplicate retains description");
    ingress(0, 3, retained, -1);
    absent(observer);
    check(!close(retained), "last close drops interest");
    option(observer, IP_MULTICAST_ALL, 1);
    ingress(0, 4, -1, -1);
    absent(observer);
    owner = endpoint(PORT, 0);
    option(owner, IP_MULTICAST_ALL, 0);
    membership(owner, IP_ADD_MEMBERSHIP, 1);
    ingress(0, 5, -1, -1);
    absent(owner);
    absent(observer);
    ingress(1, 6, owner, observer);
    membership(owner, IP_ADD_MEMBERSHIP, 0);
    ingress(0, 7, owner, observer);
    membership(owner, IP_DROP_MEMBERSHIP, 0);
    ingress(0, 8, -1, -1);
    absent(owner);
    absent(observer);
    ingress(1, 9, owner, observer);
    close(owner);
    close(observer);
    puts("MULTICAST_LIFETIME_PASS");
}

static void output(void) {
    int receiver = endpoint(PORT, GROUP);
    option(receiver, IP_MULTICAST_ALL, 0);
    membership(receiver, IP_ADD_MEMBERSHIP, 0);
    int sender = endpoint(PORT + 1, 0);
    struct ip_mreqn selected = {.imr_ifindex = (int)indices[0]};
    check(!setsockopt(sender, IPPROTO_IP, IP_MULTICAST_IF, &selected, sizeof(selected)),
          "output interface index");
    struct sockaddr_in target = address(GROUP, PORT);
    for (unsigned phase = 10; phase < 13; phase++) {
        option(sender, IP_MULTICAST_TTL, phase == 12 ? 0 : 7);
        option(sender, IP_MULTICAST_LOOP, phase == 11 ? 0 : 1);
        unsigned char payload[] = {'A', 'X', 'M', 'C', 'O', (unsigned char)phase};
        check(sendto(sender, payload, sizeof(payload), 0, (struct sockaddr*)&target,
                     sizeof(target)) == sizeof(payload),
              "multicast output acceptance");
        if (phase == 11)
            absent(receiver);
        else
            received(receiver, payload, sizeof(payload), 0x0a430102);
        control(0, phase);
    }
    control(0, 200); // Router query; peer waits for the actual current-state report.
    control(0, 201); // Older querier; peer waits for an actual IGMPv2 report.
    close(receiver);
    control(0, 202); // Last-reporter leave must reach the physical peer.
    close(sender);
    puts("MULTICAST_OUTPUT_REPORT_PASS");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(90);
    configure();
    abi();
    tcp_inheritance();
    lifetime();
    output();
    close(controls[0]);
    close(controls[1]);
    puts("MULTICAST_TESTS_PASS");
    return 0;
}
