// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

static unsigned cases;
static const char* policy = "/proc/sys/net/ipv4/igmp_max_msf";

static void need(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "IPV4_SOURCE_CAPACITY_FAIL operation=%s case=%u errno=%d\n", operation,
                cases, errno);
        exit(1);
    }
}

static void result(const char* operation, int actual, int error) {
    int observed = actual < 0 ? errno : 0;
    need(actual == (error ? -1 : 0) && observed == error, operation);
    printf("{\"operation\":\"%s\",\"returncode\":%d,\"errno\":%d}\n", operation, actual, observed);
    cases++;
}

static void set_policy(const char* value) {
    int fd = open(policy, O_WRONLY | O_CLOEXEC);
    need(fd >= 0, "open source policy");
    size_t length = strlen(value);
    need(write(fd, value, length) == (ssize_t)length && !close(fd), "write source policy");
}

static int socket_open(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    need(fd >= 0, "open source membership socket");
    return fd;
}

static void inspect(int fd, const char* operation) {
    union {
        uint64_t alignment;
        unsigned char bytes[16 + 66 * 4];
    } storage;

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    struct ip_msfilter* value = (struct ip_msfilter*)storage.bytes;
    need(inet_pton(AF_INET, "239.127.42.1", &value->imsf_multiaddr) == 1 &&
             inet_pton(AF_INET, "127.0.0.1", &value->imsf_interface) == 1,
         "query membership addresses");
    value->imsf_fmode = 0;
    value->imsf_numsrc = 66;
    socklen_t length = sizeof(storage.bytes);
    errno = 0;
    int actual = getsockopt(fd, IPPROTO_IP, IP_MSFILTER, value, &length);
    need(actual == 0 && length == 272 && value->imsf_fmode == MCAST_INCLUDE &&
             value->imsf_numsrc == 64,
         "query exact source capacity");
    for (unsigned at = 0; at < 64; at++)
        need(ntohl(value->imsf_slist[at].s_addr) == 0xc0000201U + at,
             "retain ordered admitted sources");
    for (unsigned at = 272; at < sizeof(storage.bytes); at++)
        need(storage.bytes[at] == 0xa5, "query preserves unused source slots");
    printf("{\"operation\":\"%s\",\"returncode\":0,\"errno\":0,\"length\":%u,\"mode\":%u,"
           "\"sources\":%u,\"copied\":[",
           operation, length, value->imsf_fmode, value->imsf_numsrc);
    for (unsigned at = 0; at < 64; at++)
        printf("%s%u", at ? "," : "", ntohl(value->imsf_slist[at].s_addr));
    puts("]}");
    cases++;
}

static void replace(int fd, const char* operation, unsigned count, int error) {
    union {
        uint64_t alignment;
        unsigned char bytes[16 + 65 * 4];
    } storage = {0};
    struct ip_msfilter* value = (struct ip_msfilter*)storage.bytes;
    need(inet_pton(AF_INET, "239.127.42.1", &value->imsf_multiaddr) == 1 &&
             inet_pton(AF_INET, "127.0.0.1", &value->imsf_interface) == 1,
         "replace membership addresses");
    value->imsf_fmode = count == 64 ? MCAST_INCLUDE : MCAST_EXCLUDE;
    value->imsf_numsrc = count;
    for (unsigned at = 0; at < count; at++)
        value->imsf_slist[at].s_addr = htonl(0xc0000201U + at);
    errno = 0;
    result(operation, setsockopt(fd, IPPROTO_IP, IP_MSFILTER, value, 16 + count * 4), error);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct utsname identity;
    need(!uname(&identity), "kernel identity");
    int native = !strcmp(identity.sysname, "Linux");
    if (native) {
        need(!unshare(CLONE_NEWNET), "own native network namespace");
        int fd = socket_open();
        struct ifreq link = {0};
        strcpy(link.ifr_name, "lo");
        need(!ioctl(fd, SIOCGIFFLAGS, &link), "native loopback flags");
        link.ifr_flags |= IFF_UP;
        need(!ioctl(fd, SIOCSIFFLAGS, &link) && !close(fd), "activate owned native loopback");
    }
    int fd = open(policy, O_RDONLY | O_CLOEXEC);
    need(fd >= 0, "open initial policy");
    char original[32] = {0};
    ssize_t length = read(fd, original, sizeof(original) - 1);
    need(length == 3 && !strcmp(original, "10\n") && !close(fd), "initial source policy");
    printf("{\"kernel\":\"%s\",\"native\":%s,\"owned_namespace\":%s,\"policy\":64}\n",
           identity.release, native ? "true" : "false", native ? "true" : "false");
    set_policy("64\n");
    fd = socket_open();
    for (unsigned at = 1; at <= 65; at++) {
        struct ip_mreq_source value = {0};
        need(inet_pton(AF_INET, "239.127.42.1", &value.imr_multiaddr) == 1 &&
                 inet_pton(AF_INET, "127.0.0.1", &value.imr_interface) == 1,
             "single-source membership addresses");
        value.imr_sourceaddr.s_addr = htonl(0xc0000200U + at);
        char operation[64];
        snprintf(operation, sizeof(operation), "configured-source-limit-%u", at);
        errno = 0;
        result(operation,
               setsockopt(fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &value, sizeof(value)),
               at == 65 ? ENOBUFS : 0);
    }
    inspect(fd, "configured-source-limit-state");
    need(!close(fd), "close individual source owner");
    fd = socket_open();
    struct ip_mreq member = {0};
    need(inet_pton(AF_INET, "239.127.42.1", &member.imr_multiaddr) == 1 &&
             inet_pton(AF_INET, "127.0.0.1", &member.imr_interface) == 1,
         "bulk membership addresses");
    errno = 0;
    result("configured-bulk-join",
           setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &member, sizeof(member)), 0);
    replace(fd, "configured-bulk-64", 64, 0);
    inspect(fd, "configured-bulk-64-state");
    replace(fd, "configured-bulk-65", 65, ENOBUFS);
    inspect(fd, "configured-bulk-65-state");
    need(!close(fd), "close bulk source owner");
    set_policy(original);
    need(cases == 71, "complete configured source cases");
    puts("IPV4 SOURCE CAPACITY PASS operations=71 restored_policy=10");
    return 0;
}
