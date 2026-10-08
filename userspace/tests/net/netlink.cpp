// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "net/config/routing.hpp"

static bool native;
static unsigned sequence = 100, indexes[2];

static void check(bool condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "NETLINK_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

struct Route {
    uint32_t destination = 0, gateway = 0, metric = 0;
    unsigned prefix = 0, index = 0, protocol = RTPROT_DHCP, scope = RT_SCOPE_LINK;
};

struct Packet {
    uint8_t bytes[512]{};
    nlmsghdr header{};
    size_t size = sizeof(nlmsghdr);

    Packet(unsigned type, unsigned flags) {
        header.nlmsg_type = type;
        header.nlmsg_flags = flags | NLM_F_REQUEST;
        header.nlmsg_seq = ++sequence;
        header.nlmsg_pid = 0x76543210; // Kernel authority comes from the socket port.
    }

    void attribute(unsigned type, uint32_t value) {
        rtattr field{};
        field.rta_type = type;
        field.rta_len = 8;
        memcpy(bytes + size, &field, 4);
        memcpy(bytes + size + 4, &value, 4);
        size += 8;
    }

    void route(const Route& entry, bool dump = false) {
        rtmsg body{};
        body.rtm_family = AF_INET;
        body.rtm_table = RT_TABLE_MAIN;
        body.rtm_dst_len = dump ? 0 : entry.prefix;
        body.rtm_protocol = entry.protocol;
        body.rtm_scope = dump ? 0 : entry.scope;
        body.rtm_type = dump ? 0 : RTN_UNICAST;
        memcpy(bytes + size, &body, sizeof(body));
        size += sizeof(body);
        if (!dump && entry.prefix)
            attribute(RTA_DST, htonl(entry.destination));
        if (!dump && entry.gateway)
            attribute(RTA_GATEWAY, htonl(entry.gateway));
        if (!dump && entry.metric)
            attribute(RTA_PRIORITY, entry.metric);
        if (entry.index)
            attribute(RTA_OIF, entry.index);
    }

    void finish() {
        header.nlmsg_len = size;
        memcpy(bytes, &header, sizeof(header));
    }
};

static unsigned port(int fd) {
    sockaddr_nl address{};
    socklen_t size = sizeof(address);
    check(getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) == 0 &&
              size == sizeof(address) && address.nl_family == AF_NETLINK && !address.nl_groups,
          "local name has Linux netlink shape");
    return address.nl_pid;
}

static int open_socket(unsigned type = SOCK_DGRAM) {
    int fd = socket(AF_NETLINK, type | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "create route socket");
    int one = 1;
    check(setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one)) == 0 &&
              setsockopt(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &one, sizeof(one)) == 0,
          "bounded acknowledgments and checked dump filters");
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    check(bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0 && port(fd),
          "automatic unique port binding");
    return fd;
}

static void send_packet(int fd, Packet& request) {
    request.finish();
    check(send(fd, request.bytes, request.size, 0) == ssize_t(request.size),
          "unconnected route socket sends to the kernel");
}

static size_t receive(int fd, uint8_t* bytes, size_t capacity) {
    pollfd ready{fd, POLLIN, 0};
    check(poll(&ready, 1, 4000) == 1 && (ready.revents & POLLIN), "reply becomes readable");
    sockaddr_nl sender{};
    socklen_t size = sizeof(sender);
    ssize_t count = recvfrom(fd, bytes, capacity, 0, reinterpret_cast<sockaddr*>(&sender), &size);
    check(count >= 16 && size == sizeof(sender) && sender.nl_family == AF_NETLINK &&
              !sender.nl_pid && !sender.nl_groups,
          "reply is an owned datagram from kernel port zero");
    return count;
}

static void acknowledgment(int fd, const Packet& request, int expected) {
    uint8_t bytes[8192];
    size_t size = receive(fd, bytes, sizeof(bytes));
    nlmsghdr header, echoed;
    int error;
    memcpy(&header, bytes, sizeof(header));
    memcpy(&error, bytes + sizeof(header), 4);
    memcpy(&echoed, bytes + sizeof(header) + 4, sizeof(echoed));
    check(size == 36 && header.nlmsg_len == size && header.nlmsg_type == NLMSG_ERROR &&
              header.nlmsg_flags == NLM_F_CAPPED && header.nlmsg_seq == request.header.nlmsg_seq &&
              header.nlmsg_pid == port(fd) && error == -expected &&
              !memcmp(&echoed, &request.header, sizeof(echoed)),
          "capped ACK preserves sequence, authoritative port, errno, and original header");
}

static void change(int fd, const Route& route, bool remove, int error = 0) {
    Packet request(remove ? RTM_DELROUTE : RTM_NEWROUTE,
                   NLM_F_ACK | (remove ? 0 : NLM_F_CREATE | NLM_F_EXCL));
    request.route(route);
    send_packet(fd, request);
    acknowledgment(fd, request, error);
}

static size_t routes(int fd, Route* output, size_t capacity, unsigned protocol = 0,
                     unsigned index = 0) {
    Packet request(RTM_GETROUTE, NLM_F_DUMP);
    Route filter;
    filter.protocol = protocol;
    filter.index = index;
    request.route(filter, true);
    send_packet(fd, request);
    size_t count = 0;
    for (unsigned packets = 0; packets < 16; packets++) {
        uint8_t bytes[16384];
        size_t size = receive(fd, bytes, sizeof(bytes));
        for (size_t at = 0; at < size;) {
            check(size - at >= sizeof(nlmsghdr), "multipart header is complete");
            nlmsghdr header;
            memcpy(&header, bytes + at, sizeof(header));
            check(header.nlmsg_len >= 16 && header.nlmsg_len <= size - at &&
                      header.nlmsg_seq == request.header.nlmsg_seq &&
                      header.nlmsg_pid == port(fd) && (header.nlmsg_flags & NLM_F_MULTI),
                  "multipart sequence/port/length/flags");
            if (header.nlmsg_type == NLMSG_DONE) {
                int status = -1;
                check(header.nlmsg_len == 20, "dump completion has a status");
                memcpy(&status, bytes + at + 16, 4);
                check(!status, "dump completed successfully");
                return count;
            }
            check(header.nlmsg_type == RTM_NEWROUTE && header.nlmsg_len >= 28 && count < capacity,
                  "bounded IPv4 route record");
            rtmsg body;
            memcpy(&body, bytes + at + 16, sizeof(body));
            check(body.rtm_family == AF_INET && body.rtm_type == RTN_UNICAST &&
                      body.rtm_table == RT_TABLE_MAIN && body.rtm_dst_len <= 32,
                  "main-table unicast metadata");
            Route entry;
            entry.prefix = body.rtm_dst_len;
            entry.protocol = body.rtm_protocol;
            entry.scope = body.rtm_scope;
            for (size_t field_at = 28; field_at < header.nlmsg_len;) {
                rtattr field;
                check(header.nlmsg_len - field_at >= 4, "attribute header bound");
                memcpy(&field, bytes + at + field_at, sizeof(field));
                check(field.rta_len >= 4 && field.rta_len <= header.nlmsg_len - field_at,
                      "attribute payload bound");
                if (field.rta_type == RTA_DST || field.rta_type == RTA_GATEWAY ||
                    field.rta_type == RTA_PRIORITY || field.rta_type == RTA_OIF) {
                    uint32_t value;
                    check(field.rta_len == 8, "typed route scalar length");
                    memcpy(&value, bytes + at + field_at + 4, 4);
                    if (field.rta_type == RTA_DST)
                        entry.destination = ntohl(value);
                    else if (field.rta_type == RTA_GATEWAY)
                        entry.gateway = ntohl(value);
                    else if (field.rta_type == RTA_PRIORITY)
                        entry.metric = value;
                    else
                        entry.index = value;
                }
                field_at += RTA_ALIGN(field.rta_len);
            }
            check((!protocol || entry.protocol == protocol) && (!index || entry.index == index),
                  "strict dump preserves protocol/interface filters");
            output[count++] = entry;
            at += NLMSG_ALIGN(header.nlmsg_len);
        }
    }
    check(false, "multipart dump deadline");
    return 0;
}

static bool same(const Route& a, const Route& b) {
    return a.destination == b.destination && a.prefix == b.prefix && a.gateway == b.gateway &&
           a.metric == b.metric && a.index == b.index && a.protocol == b.protocol &&
           a.scope == b.scope;
}

static size_t contains(const Route* entries, size_t count, const Route& value) {
    size_t found = 0;
    for (size_t i = 0; i < count; i++)
        found += same(entries[i], value);
    return found;
}

static void configuration(unsigned lane, unsigned request_code, uint32_t value) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "interface control socket");
    ifreq request{};
    check(if_indextoname(indexes[lane], request.ifr_name), "selected interface name");
    if (request_code == SIOCSIFFLAGS)
        request.ifr_flags = IFF_UP;
    else {
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_addr.s_addr = htonl(value);
        memcpy(&request.ifr_addr, &endpoint, sizeof(endpoint));
    }
    check(ioctl(fd, request_code, &request) == 0 && close(fd) == 0,
          "checked fixture configuration");
}

static void lifecycle(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0 && !port(fd), "unbound raw socket has port zero");
    sockaddr_nl peer{};
    socklen_t size = sizeof(peer);
    struct stat information{};
    check(getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &size) == 0 &&
              peer.nl_family == AF_NETLINK && !peer.nl_pid && !peer.nl_groups &&
              fstat(fd, &information) == 0 && S_ISSOCK(information.st_mode) &&
              (fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC),
          "kernel peer and socket file metadata");
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    check(bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "bind raw socket");
    unsigned identity = port(fd);
    check(identity && bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == -1 &&
              errno == EINVAL,
          "repeating automatic bind does not change port");
    int duplicate = dup(fd);
    check(duplicate >= 0 && port(duplicate) == identity && close(fd) == 0,
          "duplicate owns original socket identity");
    fd = open_socket();
    check(port(fd) != identity, "two descriptions cannot share an automatic port");
    local.nl_pid = identity;
    int collision = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    check(collision >= 0 &&
              bind(collision, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == -1 &&
              errno == EADDRINUSE && close(duplicate) == 0 &&
              bind(collision, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0,
          "port remains occupied until the last description closes");
    check(close(collision) == 0 && close(fd) == 0, "close lifecycle sockets");
    puts("NETLINK_LIFECYCLE_PASS");
}

static void fork_lifetime(void) {
    int fd = open_socket(), control[2];
    unsigned identity = port(fd);
    Packet queued(0x777, NLM_F_ACK);
    send_packet(fd, queued);
    check(pipe(control) == 0, "fork synchronization pipe");
    pid_t child = fork();
    check(child >= 0, "fork route socket owner");
    if (!child) {
        check(close(control[1]) == 0, "child closes synchronization writer");
        char start;
        check(read(control[0], &start, 1) == 1 && port(fd) == identity,
              "child retains original description after parent close");
        acknowledgment(fd, queued, EOPNOTSUPP);
        Packet fresh(0x777, NLM_F_ACK);
        send_packet(fd, fresh);
        acknowledgment(fd, fresh, EOPNOTSUPP);
        check(close(fd) == 0 && close(control[0]) == 0, "child releases final socket owner");
        _exit(0);
    }
    check(close(control[0]) == 0 && close(fd) == 0, "parent releases inherited socket");
    int collision = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    local.nl_pid = identity;
    check(collision >= 0 &&
              bind(collision, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == -1 &&
              errno == EADDRINUSE,
          "child keeps port occupied while parent owns no description");
    check(write(control[1], "!", 1) == 1 && close(control[1]) == 0, "release inherited reader");
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status) &&
              bind(collision, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0 &&
              close(collision) == 0,
          "child final close releases port and queued storage");
    puts("NETLINK_FORK_LIFETIME_PASS");
}

static void message_io(int fd) {
    Packet request(0x777, NLM_F_ACK);
    send_packet(fd, request);
    int queue = epoll_create1(EPOLL_CLOEXEC);
    epoll_event watch{};
    watch.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    watch.data.u64 = 0x12345678;
    check(queue >= 0 && epoll_ctl(queue, EPOLL_CTL_ADD, fd, &watch) == 0,
          "watch netlink description");
    epoll_event event{};
    check(epoll_wait(queue, &event, 1, 1000) == 1 && (event.events & EPOLLIN) &&
              event.data.u64 == watch.data.u64 && epoll_wait(queue, &event, 1, 0) == 0,
          "one-shot edge notification");
    uint8_t byte = 0;
    check(recv(fd, &byte, 1, MSG_PEEK | MSG_TRUNC) == 36 && byte == 36,
          "peek returns full length while retaining complete reply");
    check(read(fd, &byte, 0) == 0 && recv(fd, &byte, 1, MSG_PEEK | MSG_TRUNC) == 36,
          "zero descriptor read retains datagram");
    check(syscall(SYS_recvfrom, fd, 1, 36, MSG_PEEK, 0, 0) == -1 && errno == EFAULT &&
              recv(fd, &byte, 1, MSG_PEEK | MSG_TRUNC) == 36,
          "peek copy fault retains reply");
    check(syscall(SYS_recvfrom, fd, 1, 36, 0, 0, 0) == -1 && errno == EFAULT &&
              recv(fd, &byte, 1, 0) == -1 && errno == EAGAIN,
          "non-peek copy fault consumes reply");
    send_packet(fd, request);
    check(epoll_ctl(queue, EPOLL_CTL_MOD, fd, &watch) == 0 &&
              epoll_wait(queue, &event, 1, 1000) == 1,
          "rearm observes queued reply");
    uint8_t bytes[36]{};
    iovec vectors[]{{bytes, 13}, {bytes + 13, 23}};
    sockaddr_nl sender{};
    msghdr message{};
    message.msg_name = &sender;
    message.msg_namelen = sizeof(sender);
    message.msg_iov = vectors;
    message.msg_iovlen = 2;
    check(recvmsg(fd, &message, 0) == 36 && !message.msg_flags &&
              message.msg_namelen == sizeof(sender) && sender.nl_family == AF_NETLINK &&
              !sender.nl_pid && !message.msg_controllen,
          "scattered receive commits kernel sender and no control data");
    vectors[0] = {request.bytes, 7};
    vectors[1] = {request.bytes + 7, request.size - 7};
    check(writev(fd, vectors, 2) == ssize_t(request.size), "vector send is one request datagram");
    acknowledgment(fd, request, EOPNOTSUPP);
    send_packet(fd, request);
    vectors[0] = {bytes, 3};
    message.msg_iovlen = 1;
    check(recvmsg(fd, &message, MSG_TRUNC) == 36 && (message.msg_flags & MSG_TRUNC),
          "recvmsg truncation reports full length and flag");
    check(send(fd, bytes, 0, 0) == -1 && errno == ENODATA, "empty netlink sends report ENODATA");
    check(close(queue) == 0, "close epoll watcher");
    puts("NETLINK_MESSAGE_IO_PASS");
}

static Route onlink(unsigned lane, uint32_t destination, unsigned prefix, unsigned metric) {
    Route result;
    result.destination = destination;
    result.prefix = prefix;
    result.index = indexes[lane];
    result.metric = metric;
    return result;
}

static void ownership(int fd) {
    Route own = onlink(0, 0xac140000, 16, 1000);
    change(fd, own, false);
    change(fd, own, false, EEXIST);
    rtentry legacy{};
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(own.destination);
    memcpy(&legacy.rt_dst, &endpoint, sizeof(endpoint));
    endpoint.sin_addr.s_addr = htonl(0xffff0000);
    memcpy(&legacy.rt_genmask, &endpoint, sizeof(endpoint));
    endpoint.sin_addr.s_addr = htonl(0x0a170109);
    memcpy(&legacy.rt_gateway, &endpoint, sizeof(endpoint));
    char name[IF_NAMESIZE];
    check(if_indextoname(indexes[0], name), "unowned route device");
    legacy.rt_dev = name;
    legacy.rt_flags = RTF_UP | RTF_GATEWAY;
    legacy.rt_metric = 1001; // ioctl priority is metric minus one.
    int control = socket(AF_INET, SOCK_DGRAM, 0);
    check(control >= 0 && ioctl(control, SIOCADDRT, &legacy) == 0,
          "unowned routed ioctl alias coexists with owned on-link route");
    Route foreign = own;
    foreign.gateway = 0x0a170109;
    foreign.protocol = RTPROT_BOOT;
    foreign.scope = RT_SCOPE_UNIVERSE;
    Route entries[64];
    size_t count = routes(fd, entries, 64);
    check(contains(entries, count, own) == 1 && contains(entries, count, foreign) == 1,
          "dump retains protocol and scope for both aliases");
    Route wrong = own;
    wrong.protocol = RTPROT_STATIC;
    change(fd, wrong, true, ESRCH);
    check(routes(fd, entries, 64, RTPROT_DHCP, indexes[0]) == 1 && same(entries[0], own),
          "owned route is independently discoverable");
    change(fd, own, true);
    count = routes(fd, entries, 64);
    check(!contains(entries, count, own) && contains(entries, count, foreign) == 1,
          "removing owned zero-gateway route preserves unowned routed alias");
    change(fd, own, true, ESRCH);
    check(ioctl(control, SIOCDELRT, &legacy) == 0 && close(control) == 0,
          "legacy ioctl can still remove its own exact routed alias");
    Route second = onlink(1, 0xc6336400, 24, 1002);
    change(fd, second, false);
    change(fd, onlink(0, second.destination, second.prefix, second.metric), false, EEXIST);
    check(routes(fd, entries, 64, RTPROT_DHCP, indexes[1]) == 1 && same(entries[0], second),
          "exclusive alias and filtered second-interface route");
    change(fd, second, true);
    puts("NETLINK_ROUTE_OWNERSHIP_PASS");
}

static void resource_limits(int fd) {
    Route entries[32];
    for (unsigned i = 0; i < 32; i++) {
        entries[i] = onlink(i % 2, 0x64400000 + (i << 8), 24, 2000 + i);
        change(fd, entries[i], false);
    }
    change(fd, onlink(0, 0x64402000, 24, 2032), false, ENOBUFS);
    Route saved[64];
    size_t count = routes(fd, saved, 64, RTPROT_DHCP);
    check(count == 32, "route capacity does not apply a partial thirty-third route");
    for (const auto& value : entries)
        change(fd, value, true);
    check(routes(fd, saved, 64, RTPROT_DHCP) == 0, "all explicit slots reclaimed");
    puts("NETLINK_ROUTE_LIMITS_PASS count=32");
}

static void byte_quota(int fd) {
    Packet dump(RTM_GETROUTE, NLM_F_DUMP);
    Route filter;
    filter.protocol = 0;
    dump.route(filter, true);
    for (unsigned i = 0; i < 15; i++)
        send_packet(fd, dump);
    check(send(fd, dump.bytes, dump.size, 0) == -1 && errno == EAGAIN,
          "reserved dump storage reaches byte quota before packet-count quota");
    int capped = 0;
    check(setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &capped, sizeof(capped)) == 0,
          "full echo accounts for reserved bytes");
    uint8_t large[3776]{};
    nlmsghdr original{};
    original.nlmsg_len = sizeof(large);
    original.nlmsg_type = 0x777;
    original.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    original.nlmsg_seq = ++sequence;
    memcpy(large, &original, sizeof(original));
    check(send(fd, large, sizeof(large), 0) == ssize_t(sizeof(large)),
          "fifteen dump reservations and full error echo exactly fill 65536 bytes");
    pollfd writable{fd, POLLOUT, 0};
    check(poll(&writable, 1, 0) == 0, "byte exhaustion removes write readiness");
    Route own = onlink(0, 0x0a660000, 16, 4501);
    Packet mutation(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    mutation.route(own);
    mutation.finish();
    check(send(fd, mutation.bytes, mutation.size, 0) == -1 && errno == EAGAIN,
          "byte-full queue rejects route mutation before applying it");
    int observer = open_socket();
    Route saved[64];
    check(routes(observer, saved, 64, RTPROT_DHCP) == 0,
          "independent observer sees no mutation after byte-quota rejection");
    uint8_t reply[8192];
    size_t size = receive(fd, reply, sizeof(reply));
    nlmsghdr first, done;
    memcpy(&first, reply, sizeof(first));
    check(size >= 20, "reserved dump has complete multipart output");
    memcpy(&done, reply + size - 20, sizeof(done));
    check(first.nlmsg_seq == dump.header.nlmsg_seq && done.nlmsg_type == NLMSG_DONE &&
              done.nlmsg_len == 20 && done.nlmsg_seq == dump.header.nlmsg_seq,
          "reclaim one complete dump reservation");
    check(poll(&writable, 1, 0) == 1 && (writable.revents & POLLOUT),
          "releasing reserved bytes restores write readiness");
    send_packet(fd, mutation);
    for (unsigned i = 0; i < 14; i++)
        receive(fd, reply, sizeof(reply));
    size = receive(fd, reply, sizeof(reply));
    nlmsghdr header;
    int error;
    memcpy(&header, reply, sizeof(header));
    memcpy(&error, reply + 16, 4);
    check(size == sizeof(large) + 20 && header.nlmsg_len == size &&
              header.nlmsg_seq == original.nlmsg_seq && header.nlmsg_type == NLMSG_ERROR &&
              error == -EOPNOTSUPP && !memcmp(reply + 20, large, sizeof(large)),
          "large queued error keeps its entire owned request echo");
    acknowledgment(fd, mutation, 0);
    check(routes(observer, saved, 64, RTPROT_DHCP) == 1 && same(saved[0], own),
          "retry after quota recovery installs exactly the original route");
    change(fd, own, true);
    capped = 1;
    check(setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &capped, sizeof(capped)) == 0 &&
              close(observer) == 0,
          "restore capped replies and release byte-quota observer");
    puts("NETLINK_BYTE_QUOTA_PASS reserved=65536 packets=16");
}

static void uncapped_reply(int fd) {
    int value = 0;
    check(setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &value, sizeof(value)) == 0,
          "request full error echo");
    Packet request(0x777, NLM_F_ACK);
    request.bytes[request.size++] = 'A';
    send_packet(fd, request);
    uint8_t reply[128];
    size_t size = receive(fd, reply, sizeof(reply));
    nlmsghdr header;
    int error;
    memcpy(&header, reply, sizeof(header));
    memcpy(&error, reply + 16, 4);
    check(size == 40 && header.nlmsg_len == size && header.nlmsg_type == NLMSG_ERROR &&
              !header.nlmsg_flags && header.nlmsg_seq == request.header.nlmsg_seq &&
              header.nlmsg_pid == port(fd) && error == -EOPNOTSUPP &&
              !memcmp(reply + 20, request.bytes, request.size) && !reply[37] && !reply[38] &&
              !reply[39],
          "uncapped error echoes unaligned request with zero alignment padding");
    value = 1;
    check(setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &value, sizeof(value)) == 0,
          "restore bounded acknowledgments");
    puts("NETLINK_UNCAPPED_REPLY_PASS");
}

static void malformed(int fd) {
    for (unsigned kind = 0; kind < 12; kind++) {
        Packet request(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        Route candidate = onlink(0, 0x0a650000, 16, 5001);
        request.route(candidate);
        int expected = EINVAL;
        switch (kind) {
        case 0:
            request.size = 27;
            break;
        case 1:
            request.bytes[16] = AF_INET6;
            expected = EAFNOSUPPORT;
            break;
        case 2:
            request.bytes[17] = 33;
            break;
        case 3:
            request.bytes[35] = 1;
            break;
        case 4:
            request.attribute(RTA_OIF, candidate.index);
            break;
        case 5:
            request.attribute(RTA_MARK, 3);
            expected = EOPNOTSUPP;
            break;
        case 6:
            request.bytes[28] = 7;
            break;
        case 7:
            request.bytes[20] = 100;
            expected = EOPNOTSUPP;
            break;
        case 8:
            request.bytes[24] = 1;
            expected = EOPNOTSUPP;
            break;
        case 9:
            request.header.nlmsg_flags |= NLM_F_REPLACE;
            expected = EOPNOTSUPP;
            break;
        case 10: {
            uint32_t bad = 65535;
            memcpy(request.bytes + request.size - 4, &bad, 4);
            expected = ENODEV;
            break;
        }
        case 11:
            request.bytes[23] = 0;
            break;
        }
        send_packet(fd, request);
        acknowledgment(fd, request, expected);
    }
    Route entries[64];
    check(routes(fd, entries, 64, RTPROT_DHCP) == 0,
          "typed/unsupported requests cannot partially install any candidate route");
    Packet short_packet(0x777, NLM_F_ACK);
    short_packet.finish();
    check(send(fd, short_packet.bytes, 15, 0) == -1 && errno == EINVAL,
          "outer datagram validation rejects incomplete header before mutation");
    short_packet.bytes[0] = 0;
    check(send(fd, short_packet.bytes, short_packet.size, 0) == -1 && errno == EINVAL,
          "zero-length header cannot stall batch parsing");
    puts("NETLINK_MALFORMED_PASS requests=14");
}

static void configuration_adapter(int fd) {
    ax::net::Routing adapter;
    check(adapter.open() == 0, "production routing adapter opens a private kernel port");
    ax::net::Route own;
    own.destination = 0x0a630000;
    own.mask = 0xffff0000;
    own.index = indexes[0];
    own.metric = 3001;
    check(adapter.change(own, false) == 0 && adapter.change(own, false) == EEXIST,
          "adapter accepts checked installation and propagates collision");
    ax::net::Route saved[64];
    size_t count = 999;
    check(adapter.list(saved, 64, count, indexes[0], RTPROT_DHCP) == 0 && count == 1 &&
              saved[0].destination == own.destination && saved[0].mask == own.mask &&
              !saved[0].gateway && saved[0].index == own.index && saved[0].metric == own.metric &&
              saved[0].protocol == RTPROT_DHCP && saved[0].scope == RT_SCOPE_LINK,
          "adapter owns independently checked parsed route snapshot");
    Route entries[64];
    Route expected = onlink(0, own.destination, 16, own.metric);
    size_t total = routes(fd, entries, 64);
    check(contains(entries, total, expected) == 1,
          "independent observer confirms adapter mutation");
    saved[0].destination = 0xabcdef01;
    ax::net::Route original = saved[0];
    count = 999;
    check(adapter.list(saved, 0, count, indexes[0], RTPROT_DHCP) == ENOSPC && count == 999 &&
              !memcmp(saved, &original, sizeof(original)),
          "undersized list leaves caller's count and output unchanged");
    ax::net::Route invalid = own;
    invalid.metric = 0;
    check(adapter.change(invalid, true) == EINVAL, "adapter refuses wildcard priority removal");
    invalid = own;
    invalid.protocol = RTPROT_STATIC;
    check(adapter.change(invalid, true) == ESRCH && adapter.change(own, true) == 0,
          "adapter removal requires the configured ownership tag");
    check(adapter.list(nullptr, 0, count, indexes[0], RTPROT_DHCP) == 0 && !count,
          "empty owned list supports zero output capacity");
    puts("NETLINK_CONFIGURATION_ADAPTER_PASS");
}

struct BlockedWrite {
    int fd;
    msghdr message{};
    bool started = false, finished = false;
    ssize_t result = -1;
};

static void* blocked_write(void* pointer) {
    auto& operation = *static_cast<BlockedWrite*>(pointer);
    __atomic_store_n(&operation.started, true, __ATOMIC_RELEASE);
    operation.result = sendmsg(operation.fd, &operation.message, 0);
    __atomic_store_n(&operation.finished, true, __ATOMIC_RELEASE);
    return nullptr;
}

static void pressure(int fd) {
    Packet error(0x777, NLM_F_ACK);
    for (unsigned i = 0; i < 32; i++)
        send_packet(fd, error);
    check(send(fd, error.bytes, error.size, 0) == -1 && errno == EAGAIN,
          "full reply queue rejects before changing route state");
    Route own = onlink(0, 0x0a640000, 16, 4001);
    Packet request(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    request.route(own);
    request.finish();
    sockaddr_nl destination{};
    destination.nl_family = AF_NETLINK;
    iovec vectors[]{{request.bytes, 11}, {request.bytes + 11, request.size - 11}};
    BlockedWrite operation;
    operation.fd = fd;
    operation.message.msg_name = &destination;
    operation.message.msg_namelen = sizeof(destination);
    operation.message.msg_iov = vectors;
    operation.message.msg_iovlen = 2;
    check(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK) == 0, "enable blocking writer");
    int observer = dup(fd);
    pthread_t thread;
    check(observer >= 0 && pthread_create(&thread, nullptr, blocked_write, &operation) == 0,
          "start a writer against the full owned queue");
    while (!__atomic_load_n(&operation.started, __ATOMIC_ACQUIRE))
        sched_yield();
    timespec pause{0, 100000000};
    check(nanosleep(&pause, nullptr) == 0 &&
              !__atomic_load_n(&operation.finished, __ATOMIC_ACQUIRE),
          "writer remains pending under backpressure");
    size_t accepted = request.size;
    nlmsghdr accepted_header = request.header;
    memset(request.bytes, 0xa5, sizeof(request.bytes));
    destination.nl_family = AF_INET;
    vectors[0] = {reinterpret_cast<void*>(1), 4096};
    operation.message.msg_iovlen = 999;
    int pipes[2];
    check(pipe2(pipes, O_NONBLOCK | O_CLOEXEC) == 0, "create reused descriptor pipe");
    check(close(fd) == 0, "close writer's descriptor number while request retains description");
    if (pipes[1] != fd)
        check(dup2(pipes[1], fd) == fd, "replace original number with unrelated pipe writer");
    for (unsigned i = 0; i < 32; i++)
        acknowledgment(observer, error, EOPNOTSUPP);
    check(pthread_join(thread, nullptr) == 0 && operation.result == ssize_t(accepted),
          "blocked operation completes with original accepted message length");
    request.header = accepted_header;
    acknowledgment(observer, request, 0);
    char byte;
    check(read(pipes[0], &byte, 1) == -1 && errno == EAGAIN,
          "reused descriptor receives no pending socket bytes");
    int check_fd = open_socket();
    Route entries[64];
    size_t count = routes(check_fd, entries, 64, RTPROT_DHCP);
    check(count == 1 && contains(entries, count, own) == 1,
          "retained vectors, destination, and payload install only original route");
    change(check_fd, own, true);
    check(close(check_fd) == 0 && close(observer) == 0,
          "release original owned socket descriptions");
    if (fd != pipes[0] && fd != pipes[1])
        check(close(fd) == 0, "close reused writer number");
    check(close(pipes[0]) == 0 && close(pipes[1]) == 0, "close pressure test pipe");
    puts("NETLINK_PRESSURE_LIFETIME_PASS replies=32");
}

static void socket_limits(void) {
    int sockets[64];
    size_t count = 0;
    while (count < 64) {
        int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) {
            check(errno == ENFILE, "socket pool returns ENFILE at the documented bound");
            break;
        }
        sockets[count++] = fd;
    }
    check(count == 63, "one existing and sixty-three new descriptions fill sixty-four slots");
    for (size_t i = 0; i < count; i++)
        check(close(sockets[i]) == 0, "closed socket returns its pool slot");
    int fd = open_socket();
    check(close(fd) == 0, "socket pool reusable after final close");
    puts("NETLINK_SOCKET_LIMITS_PASS count=64");
}

static void routed_packet(unsigned lane, unsigned stage, uint32_t destination) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
    char interface[IF_NAMESIZE];
    check(fd >= 0 && if_indextoname(indexes[lane], interface) &&
              setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) == 0,
          "routed probe uses selected physical interface");
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(46000 + lane);
    local.sin_addr.s_addr = htonl(0x0a170128 + (lane << 8));
    check(bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0,
          "routed probe owns source address and port");
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(46002);
    peer.sin_addr.s_addr = htonl(destination);
    const uint8_t payload[]{'A', 'X', 'N', 'R', uint8_t(lane), uint8_t(stage), 0x73, 0x91};
    check(sendto(fd, payload, sizeof(payload), 0, reinterpret_cast<sockaddr*>(&peer),
                 sizeof(peer)) == ssize_t(sizeof(payload)),
          "route-selected UDP output accepted");
    pollfd ready{fd, POLLIN, 0};
    check(poll(&ready, 1, 4000) == 1 && (ready.revents & POLLIN),
          "independent host observes routed packet and echoes it");
    uint8_t reply[sizeof(payload) + 1];
    sockaddr_in source{};
    socklen_t length = sizeof(source);
    check(recvfrom(fd, reply, sizeof(reply), 0, reinterpret_cast<sockaddr*>(&source), &length) ==
                  ssize_t(sizeof(payload)) &&
              length == sizeof(source) && source.sin_family == AF_INET &&
              source.sin_port == peer.sin_port && source.sin_addr.s_addr == peer.sin_addr.s_addr &&
              !memcmp(reply, payload, sizeof(payload)) && close(fd) == 0,
          "routed echo retains host tuple, exact payload, and interface isolation");
}

static void packet_routes(int fd) {
    for (unsigned lane = 0; lane < 2; lane++) {
        Route gateway = onlink(lane, 0, 0, 6000 + lane);
        gateway.gateway = 0x0a170101 + (lane << 8);
        gateway.scope = RT_SCOPE_UNIVERSE;
        change(fd, gateway, false);
        routed_packet(lane, 0, 0xcb00712c);
        Route direct = onlink(lane, 0x0af40000, 16, 6100 + lane);
        change(fd, direct, false);
        routed_packet(lane, 1, 0x0af4002c);
        rtentry foreign{};
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_addr.s_addr = htonl(direct.destination);
        memcpy(&foreign.rt_dst, &endpoint, sizeof(endpoint));
        endpoint.sin_addr.s_addr = htonl(0xffff0000);
        memcpy(&foreign.rt_genmask, &endpoint, sizeof(endpoint));
        endpoint.sin_addr.s_addr = htonl(0x0a170109 + (lane << 8));
        memcpy(&foreign.rt_gateway, &endpoint, sizeof(endpoint));
        char name[IF_NAMESIZE];
        check(if_indextoname(indexes[lane], name), "physical foreign route device");
        foreign.rt_dev = name;
        foreign.rt_flags = RTF_UP | RTF_GATEWAY;
        foreign.rt_metric = direct.metric + 1;
        int control = socket(AF_INET, SOCK_DGRAM, 0);
        check(control >= 0 && ioctl(control, SIOCADDRT, &foreign) == 0,
              "install separate unowned routed alias for packet proof");
        change(fd, direct, true);
        routed_packet(lane, 2, 0x0af4002c);
        check(ioctl(control, SIOCDELRT, &foreign) == 0 && close(control) == 0,
              "remove isolated unowned fixture route after preserved forwarding proof");
        change(fd, gateway, true);
    }
    puts("NETLINK_ROUTED_PACKETS_PASS count=6");
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    puts("NETLINK_READY");
    native = argc == 2 && !strcmp(argv[1], "--native");
    indexes[0] = if_nametoindex("eth0");
    indexes[1] = if_nametoindex("eth1");
    check(indexes[0] && indexes[1] && indexes[0] != indexes[1], "two isolated Ethernet interfaces");
    for (unsigned lane = 0; lane < 2; lane++) {
        configuration(lane, SIOCSIFFLAGS, 0);
        configuration(lane, SIOCSIFADDR, 0x0a170128 + (lane << 8));
        configuration(lane, SIOCSIFNETMASK, 0xffffff00);
    }
    lifecycle();
    fork_lifetime();
    int fd = open_socket();
    message_io(fd);
    uncapped_reply(fd);
    ownership(fd);
    configuration_adapter(fd);
    if (!native) {
        malformed(fd);
        resource_limits(fd);
        byte_quota(fd);
        pressure(fd);
        fd = open_socket();
        socket_limits();
        packet_routes(fd);
    }
    check(close(fd) == 0, "close final route socket");
    for (unsigned lane = 0; lane < 2; lane++)
        configuration(lane, SIOCSIFADDR, 0);
    puts("NETLINK_TESTS_PASS");
}
