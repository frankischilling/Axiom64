// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_ISOLATION"
#define IPV6_BARRIER_PROTOCOL 0x88c6
#define IPV6_BARRIER_MAGIC "IP6I"
#include "../ipv6_fixture.h"
#include <netinet/tcp.h>
#include <signal.h>

static void record(const char* text, int length, size_t capacity) {
    check(length > 0 && (size_t)length < capacity &&
              write(STDOUT_FILENO, text, (size_t)length) == length,
          "complete isolation result record");
}

static void pattern(unsigned char* bytes, size_t size, unsigned round, unsigned lane,
                    unsigned tag) {
    for (size_t n = 0; n < size; n++)
        bytes[n] = (unsigned char)(round * 53 + lane * 97 + tag * 29 + n * 7);
}

static void device_options(void) {
    long page = sysconf(_SC_PAGESIZE);
    check(page > 0, "actual device-query page size");
    unsigned char* memory =
        mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(memory != MAP_FAILED && !mprotect(memory + page, (size_t)page, PROT_NONE),
          "actual device-query protected page");
    for (unsigned family_index = 0; family_index < 2; family_index++) {
        int family = family_index ? AF_INET6 : AF_INET;
        for (int type = SOCK_STREAM; type <= SOCK_RAW; type++) {
            int protocol = type == SOCK_RAW ? (family_index ? IPPROTO_ICMPV6 : IPPROTO_ICMP) : 0;
            int fd = socket(family, type | SOCK_CLOEXEC, protocol);
            check(fd >= 0, "actual device-query socket family and transport");
            unsigned queries = 0;
            const unsigned capacities[] = {0, 1, 15, 16, 32};
            for (unsigned n = 0; n < sizeof(capacities) / sizeof(capacities[0]); n++) {
                socklen_t length = capacities[n];
                check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, memory + page, &length) &&
                          !length,
                      "unbound device query ignores the output pointer");
                queries++;
            }
            socklen_t length = (socklen_t)-1;
            errno = 0;
            check(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, NULL, &length) == -1 &&
                      errno == EINVAL && length == (socklen_t)-1,
                  "negative device-query length precedes output access");
            queries++;
            unsigned char bytes[32];
            memset(bytes, 0xa5, sizeof(bytes));
            errno = 0;
            check(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bytes, (socklen_t*)(memory + page)) ==
                          -1 &&
                      errno == EFAULT && bytes[0] == 0xa5,
                  "device-query length is read before output publication");
            queries++;
            check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 5),
                  "actual device-query binding");
            for (unsigned capacity = 0; capacity < IF_NAMESIZE; capacity++) {
                length = capacity;
                errno = 0;
                check(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, memory + page, &length) == -1 &&
                          errno == EINVAL && length == capacity,
                      "bound device query requires IF_NAMESIZE before output access");
                queries++;
            }
            for (unsigned capacity = 16; capacity <= 32; capacity += 16) {
                memset(bytes, 0xa5, sizeof(bytes));
                length = capacity;
                check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bytes, &length) && length == 5 &&
                          !memcmp(bytes, "eth0", 5),
                      "actual device name and terminating byte");
                for (unsigned n = length; n < sizeof(bytes); n++)
                    check(bytes[n] == 0xa5, "device query preserves all trailing bytes");
                queries++;
            }
            length = 16;
            errno = 0;
            check(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, memory + page, &length) == -1 &&
                      errno == EFAULT && length == 16,
                  "device-name output fault preserves the result length");
            queries++;
            for (unsigned prefix = 0; prefix <= 5; prefix++) {
                memset(memory + page - 16, 0xa5, 16);
                length = 16;
                errno = 0;
                int result =
                    getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, memory + page - prefix, &length);
                check((prefix == 5 ? result == 0 && length == 5
                                   : result == -1 && errno == EFAULT && length == 16) &&
                          !memcmp(memory + page - prefix, "eth0", prefix) &&
                          memory[page - prefix - 1] == 0xa5,
                      "device query preserves actual partial-copy bytes and order");
                queries++;
            }
            check(!mprotect(memory + page, (size_t)page, PROT_READ | PROT_WRITE),
                  "prepare actual device-query length publication fault");
            unsigned char* length_pointer = memory + page - 2;
            uint32_t requested = 16, actual;
            memcpy(length_pointer, &requested, sizeof(requested));
            check(!mprotect(memory + page, (size_t)page, PROT_READ),
                  "protect the device-query result-length suffix");
            memset(bytes, 0xa5, sizeof(bytes));
            errno = 0;
            int result =
                getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bytes, (socklen_t*)length_pointer);
            memcpy(&actual, length_pointer, sizeof(actual));
            check(result == -1 && errno == EFAULT && actual == 5 && !memcmp(bytes, "eth0", 5) &&
                      bytes[5] == 0xa5,
                  "device name precedes actual partial result-length publication");
            queries++;
            check(!mprotect(memory + page, (size_t)page, PROT_NONE),
                  "restore actual device-query guard page");
            int alias = dup(fd);
            check(alias >= 0 && !setsockopt(alias, SOL_SOCKET, SO_BINDTODEVICE, "eth1", 5) &&
                      !close(alias),
                  "actual shared device binding survives alias release");
            length = sizeof(bytes);
            check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bytes, &length) && length == 5 &&
                      !memcmp(bytes, "eth1", 5),
                  "device query observes the shared description binding");
            queries++;
            check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3),
                  "actual device-query loopback binding");
            length = sizeof(bytes);
            check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bytes, &length) && length == 3 &&
                      !memcmp(bytes, "lo", 3),
                  "actual loopback device name");
            queries++;
            check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, NULL, 0),
                  "actual shared device-binding release");
            for (unsigned capacity = 0; capacity <= 16; capacity += 16) {
                length = capacity;
                check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, memory + page, &length) &&
                          !length,
                      "released device query has no name bytes");
                queries++;
            }
            check(queries == 37 && !close(fd), "complete device-query description release");
            char text[160];
            int count = snprintf(text, sizeof(text),
                                 "TCP6_ISOLATION_OPTION_PASS family=%d type=%d queries=%u\n",
                                 family, type, queries);
            record(text, count, sizeof(text));
        }
    }
    check(!munmap(memory, (size_t)page * 2), "device-query guard pages released");
}

static void names(int fd, unsigned round, unsigned lane) {
    struct sockaddr_in6 actual, wanted = address(lane, 2, 49200 + round, 1);
    socklen_t size = sizeof(actual);
    check(!getsockname(fd, (struct sockaddr*)&actual, &size) && size == sizeof(actual) &&
              !memcmp(&actual, &wanted, sizeof(actual)),
          "actual duplicate local tuple and incoming zone");
    unsigned local_scope = actual.sin6_scope_id;
    unsigned local_port = ntohs(actual.sin6_port);
    size = sizeof(actual);
    wanted = address(lane, 1, 49300 + round, 1);
    check(!getpeername(fd, (struct sockaddr*)&actual, &size) && size == sizeof(actual) &&
              !memcmp(&actual, &wanted, sizeof(actual)),
          "actual duplicate peer tuple and incoming zone");
    char device[16], expected[16];
    snprintf(expected, sizeof(expected), "eth%u", lane);
    socklen_t device_size = sizeof(device);
    check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, &device_size) &&
              device_size == strlen(expected) + 1 && !memcmp(device, expected, device_size),
          "actual scoped stream device binding readback");
    char text[256];
    int length = snprintf(text, sizeof(text),
                          "TCP6_ISOLATION_NAME_PASS round=%u lane=%u explicit_device=%u index=%u "
                          "local_scope=%u peer_scope=%u local_port=%u peer_port=%u\n",
                          round, lane, round / 2, indices[lane], local_scope, actual.sin6_scope_id,
                          local_port, ntohs(actual.sin6_port));
    record(text, length, sizeof(text));
}

static void empty(int fd) {
    check(get(fd, SOL_SOCKET, SO_ERROR) == 0, "unaffected zone has no socket error");
    struct pollfd event = {.fd = fd, .events = POLLIN | POLLERR};
    check(poll(&event, 1, 0) == 0, "unaffected zone has no readable or failed stream");
    unsigned char byte;
    errno = 0;
    check(recv(fd, &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "no bytes cross into the unaffected interface zone");
}

static void incoming(int fd, unsigned round, unsigned lane, unsigned tag) {
    unsigned char actual[32], wanted[32];
    pattern(wanted, sizeof(wanted), round, lane, tag);
    size_t offset = 0;
    while (offset < sizeof(actual)) {
        readable(fd, POLLIN);
        ssize_t size = recv(fd, actual + offset, sizeof(actual) - offset, MSG_DONTWAIT);
        check(size > 0 && (size_t)size <= sizeof(actual) - offset,
              "actual complete scoped stream input");
        offset += (size_t)size;
    }
    check(!memcmp(actual, wanted, sizeof(actual)), "exact bytes belong to the receiving zone");
    char text[192];
    int length =
        snprintf(text, sizeof(text), "TCP6_ISOLATION_DATA_PASS round=%u lane=%u tag=%u bytes=32\n",
                 round, lane, tag);
    record(text, length, sizeof(text));
}

static void outgoing(int fd, unsigned round, unsigned lane, unsigned tag, size_t size) {
    unsigned char bytes[32];
    check(size <= sizeof(bytes), "bounded scoped stream output");
    pattern(bytes, size, round, lane, tag);
    check(send(fd, bytes, size, MSG_NOSIGNAL) == (ssize_t)size,
          "actual complete scoped stream output");
}

static void one(unsigned round) {
    int descriptors[2], aliases[2];
    unsigned base = round * 8, victim = round % 2, survivor = 1 - victim;
    for (unsigned lane = 0; lane < 2; lane++) {
        descriptors[lane] = create(SOCK_STREAM | SOCK_NONBLOCK);
        option(descriptors[lane], IPPROTO_IPV6, IPV6_V6ONLY, 1);
        option(descriptors[lane], IPPROTO_TCP, TCP_NODELAY, 1);
        if (round / 2) {
            char name[16];
            snprintf(name, sizeof(name), "eth%u", lane);
            check(
                !setsockopt(descriptors[lane], SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
                "explicit scoped stream device binding");
        }
        bind_address(descriptors[lane], address(lane, 2, 49200 + round, 1));
        struct sockaddr_in6 peer = address(lane, 1, 49300 + round, 1);
        errno = 0;
        check(connect(descriptors[lane], (struct sockaddr*)&peer, sizeof(peer)) == -1 &&
                  errno == EINPROGRESS,
              "actual asynchronous scoped stream open");
        readable(descriptors[lane], POLLOUT);
        check(get(descriptors[lane], SOL_SOCKET, SO_ERROR) == 0,
              "actual scoped three-way handshake");
        names(descriptors[lane], round, lane);
        aliases[lane] = dup(descriptors[lane]);
        check(aliases[lane] >= 0, "actual shared scoped stream description");
    }
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, base + 1);
    for (unsigned step = 0; step < 2; step++) {
        unsigned lane = 1 - step;
        barrier(lane, base + 2);
        incoming(aliases[lane], round, lane, 0);
        empty(descriptors[1 - lane]);
    }
    for (unsigned lane = 0; lane < 2; lane++)
        outgoing(descriptors[lane], round, lane, 2, 32);
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, base + 3);
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, base + 4);
    readable(descriptors[victim], POLLERR);
    int error = get(aliases[victim], SOL_SOCKET, SO_ERROR);
    check(error == ECONNRESET && get(descriptors[victim], SOL_SOCKET, SO_ERROR) == 0,
          "one reset error is shared and consumed once in its actual zone");
    empty(aliases[survivor]);
    check(!close(aliases[victim]) && !close(descriptors[victim]),
          "all reset-zone references released");
    char text[192];
    int length = snprintf(text, sizeof(text),
                          "TCP6_ISOLATION_RESET_PASS round=%u victim=%u error=104 "
                          "consumed=0 survivor_error=0\n",
                          round, victim);
    record(text, length, sizeof(text));
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, base + 5);
    incoming(descriptors[survivor], round, survivor, 1);
    outgoing(aliases[survivor], round, survivor, 3, 16);
    check(!shutdown(descriptors[survivor], SHUT_WR), "surviving zone acknowledged half-close");
    readable(aliases[survivor], POLLIN);
    unsigned char byte;
    check(recv(aliases[survivor], &byte, 1, MSG_DONTWAIT) == 0,
          "surviving zone receives actual peer FIN and EOF");
    check(!close(aliases[survivor]) && !close(descriptors[survivor]),
          "all surviving-zone references released");
    for (unsigned lane = 0; lane < 2; lane++)
        barrier(lane, base + 6);
    length = snprintf(text, sizeof(text), "TCP6_ISOLATION_CLOSE_PASS round=%u survivor=%u eof=1\n",
                      round, survivor);
    record(text, length, sizeof(text));
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")), "known isolation invocation");
    check(!close(fixture_interfaces()), "scoped isolation interface setup");
    device_options();
    for (unsigned round = 0; round < 4; round++)
        one(round);
    for (unsigned lane = 0; lane < 2; lane++)
        check(!close(packets[lane]), "scoped isolation Ethernet channel released");
    const char complete[] = "TCP6_ISOLATION_PASS rounds=4 zones=2 bytes_each=32 quiet_ms=50\n";
    record(complete, sizeof(complete) - 1, sizeof(complete));
    return 0;
}
