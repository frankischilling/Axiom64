// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

/* The same operations and expectations run on native Linux and in the guest.
 * Native setup creates its own network namespace; guest loopback is already up.
 * Both Linux 6.6 and 6.17 were observed before fixing these ABI expectations. */
struct expectation {
    const char* operation;
    int result, error;
    unsigned length, mode, count, copied[16];
};
static const struct expectation expected[] = {
    {"get-before-join", -1, 99, 48, 0, 8, {0}},
    {"block-before-join", -1, 22, 0, 0, 0, {0}},
    {"join-source-a", 0, 0, 0, 0, 0, {0}},
    {"get-source-a", 0, 0, 20, 1, 1, {3221225985U}},
    {"join-source-a-again", -1, 99, 0, 0, 0, {0}},
    {"join-source-b", 0, 0, 0, 0, 0, {0}},
    {"get-two-sources", 0, 0, 24, 1, 2, {3221225985U, 3221225986U}},
    {"get-one-slot", 0, 0, 20, 1, 2, {3221225985U}},
    {"get-zero-slots", 0, 0, 16, 1, 2, {0}},
    {"block-include", -1, 22, 0, 0, 0, {0}},
    {"drop-source-a", 0, 0, 0, 0, 0, {0}},
    {"get-after-drop-a", 0, 0, 20, 1, 1, {3221225986U}},
    {"drop-last-source", 0, 0, 0, 0, 0, {0}},
    {"get-after-last-drop", -1, 99, 48, 0, 8, {0}},
    {"asm-join", 0, 0, 0, 0, 0, {0}},
    {"block-source-a", 0, 0, 0, 0, 0, {0}},
    {"block-source-a-again", -1, 99, 0, 0, 0, {0}},
    {"get-exclude-a", 0, 0, 20, 0, 1, {3221225985U}},
    {"join-source-in-nonempty-exclude", -1, 22, 0, 0, 0, {0}},
    {"unblock-source-a", 0, 0, 0, 0, 0, {0}},
    {"get-exclude-empty", 0, 0, 16, 0, 0, {0}},
    {"join-source-in-empty-exclude", -1, 22, 0, 0, 0, {0}},
    {"get-after-empty-mode-switch", 0, 0, 16, 0, 0, {0}},
    {"drop-group", 0, 0, 0, 0, 0, {0}},
    {"replace-before-join", -1, 22, 0, 0, 0, {0}},
    {"asm-join-for-replace", 0, 0, 0, 0, 0, {0}},
    {"replace-exclude-two", 0, 0, 0, 0, 0, {0}},
    {"get-replaced-exclude", 0, 0, 24, 0, 2, {3221225985U, 3221225986U}},
    {"replace-duplicate-sources", 0, 0, 0, 0, 0, {0}},
    {"get-duplicate-sources", 0, 0, 28, 0, 3, {3221225985U, 3221225985U, 3221225987U}},
    {"replace-invalid-mode", -1, 22, 0, 0, 0, {0}},
    {"get-after-invalid-mode", 0, 0, 28, 0, 3, {3221225985U, 3221225985U, 3221225987U}},
    {"replace-include-empty", 0, 0, 0, 0, 0, {0}},
    {"get-after-empty-include", -1, 99, 48, 0, 8, {0}},
    {"source-limit-1", 0, 0, 0, 0, 0, {0}},
    {"source-limit-2", 0, 0, 0, 0, 0, {0}},
    {"source-limit-3", 0, 0, 0, 0, 0, {0}},
    {"source-limit-4", 0, 0, 0, 0, 0, {0}},
    {"source-limit-5", 0, 0, 0, 0, 0, {0}},
    {"source-limit-6", 0, 0, 0, 0, 0, {0}},
    {"source-limit-7", 0, 0, 0, 0, 0, {0}},
    {"source-limit-8", 0, 0, 0, 0, 0, {0}},
    {"source-limit-9", 0, 0, 0, 0, 0, {0}},
    {"source-limit-10", 0, 0, 0, 0, 0, {0}},
    {"source-limit-11", -1, 105, 0, 0, 0, {0}},
    {"source-limit-12", -1, 105, 0, 0, 0, {0}},
    {"get-source-limit",
     0,
     0,
     56,
     1,
     10,
     {3221225985U, 3221225986U, 3221225987U, 3221225988U, 3221225989U, 3221225990U, 3221225991U,
      3221225992U, 3221225993U, 3221225994U}},
    {"bulk-join", 0, 0, 0, 0, 0, {0}},
    {"bulk-eleven", -1, 105, 0, 0, 0, {0}},
    {"bulk-eleven-state", 0, 0, 16, 0, 0, {0}},
    {"bulk-sixteen", -1, 105, 0, 0, 0, {0}},
    {"bulk-sixteen-state", 0, 0, 16, 0, 0, {0}},
    {"bulk-reset-exclude-empty", 0, 0, 0, 0, 0, {0}},
    {"add-source-after-explicit-empty-reset", 0, 0, 0, 0, 0, {0}},
    {"get-after-explicit-empty-reset", 0, 0, 20, 1, 1, {3221225985U}},
    {"generic-block-before-join", -1, 22, 0, 0, 0, {0}},
    {"generic-source-join-a", 0, 0, 0, 0, 0, {0}},
    {"generic-source-join-b", 0, 0, 0, 0, 0, {0}},
    {"generic-get-two", 0, 0, 400, 1, 2, {3221225985U, 3221225986U}},
    {"generic-get-one-slot", 0, 0, 272, 1, 2, {3221225985U}},
    {"generic-get-zero-slots", 0, 0, 144, 1, 2, {0}},
    {"generic-duplicate-source", -1, 99, 0, 0, 0, {0}},
    {"generic-drop-source-a", 0, 0, 0, 0, 0, {0}},
    {"generic-drop-source-b", 0, 0, 0, 0, 0, {0}},
    {"generic-after-last-drop", -1, 99, 1168, 0, 8, {0}},
    {"generic-asm-join", 0, 0, 0, 0, 0, {0}},
    {"generic-block-a", 0, 0, 0, 0, 0, {0}},
    {"generic-exclude-a", 0, 0, 272, 0, 1, {3221225985U}},
    {"generic-unblock-a", 0, 0, 0, 0, 0, {0}},
    {"generic-group-leave", 0, 0, 0, 0, 0, {0}},
    {"tcp-generic-asm", 0, 0, 0, 0, 0, {0}},
    {"tcp-generic-source", 0, 0, 0, 0, 0, {0}},
    {"tcp-generic-filter", 0, 0, 272, 1, 1, {3221225985U}},
    {"tcp-asm", -1, 71, 0, 0, 0, {0}},
    {"tcp-source", 0, 0, 0, 0, 0, {0}},
    {"tcp-filter", 0, 0, 20, 1, 1, {3221225985U}},
    {"raw-asm", 0, 0, 0, 0, 0, {0}},
    {"raw-source", 0, 0, 0, 0, 0, {0}},
    {"raw-filter", 0, 0, 20, 1, 1, {3221225985U}},
};
static unsigned observed;

static const struct expectation* check_result(const char* label, int code, int error) {
    if (observed >= sizeof(expected) / sizeof(expected[0]) ||
        strcmp(label, expected[observed].operation) || code != expected[observed].result ||
        error != expected[observed].error) {
        fprintf(stderr, "FAIL operation=%s result=%d errno=%d position=%u\n", label, code, error,
                observed);
        exit(1);
    }
    return &expected[observed++];
}

static const char* group = "239.127.42.1";

static void require(int okay, const char* why) {
    if (!okay) {
        fprintf(stderr, "FAIL %s errno=%d\n", why, errno);
        exit(1);
    }
}

static int open_socket(int type) {
    int fd = socket(AF_INET, type | SOCK_CLOEXEC, type == SOCK_RAW ? IPPROTO_UDP : 0);
    require(fd >= 0, "real socket");
    return fd;
}

static void result(const char* label, int code) {
    int error = code < 0 ? errno : 0;
    printf("{\"operation\":\"%s\",\"returncode\":%d,\"errno\":%d}\n", label, code, error);
    check_result(label, code, error);
}

static void member(int fd, const char* label, int option) {
    struct ip_mreq value = {0};
    inet_pton(AF_INET, group, &value.imr_multiaddr);
    inet_pton(AF_INET, "127.0.0.1", &value.imr_interface);
    errno = 0;
    result(label, setsockopt(fd, IPPROTO_IP, option, &value, sizeof(value)));
}

static void source(int fd, const char* label, int option, unsigned address) {
    struct ip_mreq_source value = {0};
    inet_pton(AF_INET, group, &value.imr_multiaddr);
    inet_pton(AF_INET, "127.0.0.1", &value.imr_interface);
    value.imr_sourceaddr.s_addr = htonl(0xc0000200U + address);
    errno = 0;
    result(label, setsockopt(fd, IPPROTO_IP, option, &value, sizeof(value)));
}

static void get(int fd, const char* label, unsigned capacity) {
    union {
        unsigned long long alignment;
        unsigned char bytes[16 + 32 * 4];
    } storage = {0};
    struct ip_msfilter* value = (struct ip_msfilter*)storage.bytes;
    inet_pton(AF_INET, group, &value->imsf_multiaddr);
    inet_pton(AF_INET, "127.0.0.1", &value->imsf_interface);
    value->imsf_numsrc = capacity;
    socklen_t length = 16 + capacity * 4;
    errno = 0;
    int code = getsockopt(fd, IPPROTO_IP, IP_MSFILTER, value, &length);
    int error = code < 0 ? errno : 0;
    printf("{\"operation\":\"%s\",\"returncode\":%d,\"errno\":%d,\"length\":%u,\"mode\":%u,"
           "\"sources\":%u,\"copied\":[",
           label, code, error, length, value->imsf_fmode, value->imsf_numsrc);
    for (unsigned at = 0; code == 0 && at < capacity && at < value->imsf_numsrc; at++)
        printf("%s%u", at ? "," : "", ntohl(value->imsf_slist[at].s_addr));
    puts("]}");
    const struct expectation* row = check_result(label, code, error);
    if (!code) {
        require(length == row->length && value->imsf_fmode == row->mode &&
                    value->imsf_numsrc == row->count,
                "legacy source-filter query state");
        for (unsigned at = 0; at < capacity && at < value->imsf_numsrc; at++)
            require(ntohl(value->imsf_slist[at].s_addr) == row->copied[at],
                    "legacy source-filter query order");
    }
}

static void replace(int fd, const char* label, unsigned mode, unsigned count, int duplicate) {
    union {
        unsigned long long alignment;
        unsigned char bytes[16 + 32 * 4];
    } storage = {0};
    struct ip_msfilter* value = (struct ip_msfilter*)storage.bytes;
    inet_pton(AF_INET, group, &value->imsf_multiaddr);
    inet_pton(AF_INET, "127.0.0.1", &value->imsf_interface);
    value->imsf_fmode = mode;
    value->imsf_numsrc = count;
    for (unsigned at = 0; at < count; at++)
        value->imsf_slist[at].s_addr = htonl(0xc0000201U + (duplicate && at == 1 ? 0 : at));
    errno = 0;
    result(label, setsockopt(fd, IPPROTO_IP, IP_MSFILTER, value, 16 + count * 4));
}

static void group_source(int fd, const char* label, int option, unsigned source) {
    struct group_source_req value = {0};
    value.gsr_interface = if_nametoindex("lo");
    struct sockaddr_in* address = (struct sockaddr_in*)&value.gsr_group;
    address->sin_family = AF_INET;
    inet_pton(AF_INET, group, &address->sin_addr);
    address = (struct sockaddr_in*)&value.gsr_source;
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(0xc0000200U + source);
    errno = 0;
    result(label, setsockopt(fd, IPPROTO_IP, option, &value, sizeof(value)));
}

static void probe_group_member(int fd, const char* label, int option) {
    struct group_req value = {0};
    value.gr_interface = if_nametoindex("lo");
    struct sockaddr_in* address = (struct sockaddr_in*)&value.gr_group;
    address->sin_family = AF_INET;
    inet_pton(AF_INET, group, &address->sin_addr);
    errno = 0;
    result(label, setsockopt(fd, IPPROTO_IP, option, &value, sizeof(value)));
}

static void get_group(int fd, const char* label, unsigned capacity) {
    union {
        unsigned long long alignment;
        unsigned char bytes[144 + 8 * 128];
    } storage = {0};
    struct group_filter* value = (struct group_filter*)storage.bytes;
    value->gf_interface = if_nametoindex("lo");
    struct sockaddr_in* address = (struct sockaddr_in*)&value->gf_group;
    address->sin_family = AF_INET;
    inet_pton(AF_INET, group, &address->sin_addr);
    value->gf_numsrc = capacity;
    socklen_t length = 144 + capacity * 128;
    errno = 0;
    int code = getsockopt(fd, IPPROTO_IP, MCAST_MSFILTER, value, &length);
    int error = code < 0 ? errno : 0;
    printf("{\"operation\":\"%s\",\"returncode\":%d,\"errno\":%d,\"length\":%u,\"mode\":%u,"
           "\"sources\":%u,\"copied\":[",
           label, code, error, length, value->gf_fmode, value->gf_numsrc);
    for (unsigned at = 0; code == 0 && at < capacity && at < value->gf_numsrc; at++) {
        address = (struct sockaddr_in*)&value->gf_slist[at];
        require(address->sin_family == AF_INET, "actual generic IPv4 source family");
        printf("%s%u", at ? "," : "", ntohl(address->sin_addr.s_addr));
    }
    puts("]}");
    const struct expectation* row = check_result(label, code, error);
    if (!code) {
        require(length == row->length && value->gf_fmode == row->mode &&
                    value->gf_numsrc == row->count,
                "generic source-filter query state");
        for (unsigned at = 0; at < capacity && at < value->gf_numsrc; at++) {
            address = (struct sockaddr_in*)&value->gf_slist[at];
            require(ntohl(address->sin_addr.s_addr) == row->copied[at],
                    "generic source-filter query order");
        }
    }
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    require(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")), "test arguments");
    if (argc == 2) {
        require(!unshare(CLONE_NEWNET), "owned network namespace");
        int control = open_socket(SOCK_DGRAM);
        struct ifreq request = {0};
        strcpy(request.ifr_name, "lo");
        require(!ioctl(control, SIOCGIFFLAGS, &request), "private loopback flags");
        request.ifr_flags |= IFF_UP;
        require(!ioctl(control, SIOCSIFFLAGS, &request), "private loopback activation");
        close(control);
    }
    require(if_nametoindex("lo") != 0, "actual loopback interface index");
    struct utsname kernel;
    require(!uname(&kernel), "actual kernel");
    printf("{\"kernel\":\"%s\",\"mreq_source_bytes\":%zu,\"msfilter_prefix\":%zu,\"group_req_"
           "bytes\":%zu,\"group_source_bytes\":%zu,\"group_filter_prefix\":%zu}\n",
           kernel.release, sizeof(struct ip_mreq_source), (size_t)IP_MSFILTER_SIZE(0),
           sizeof(struct group_req), sizeof(struct group_source_req), (size_t)GROUP_FILTER_SIZE(0));
    int fd = open_socket(SOCK_DGRAM);
    get(fd, "get-before-join", 8);
    source(fd, "block-before-join", IP_BLOCK_SOURCE, 1);
    source(fd, "join-source-a", IP_ADD_SOURCE_MEMBERSHIP, 1);
    get(fd, "get-source-a", 8);
    source(fd, "join-source-a-again", IP_ADD_SOURCE_MEMBERSHIP, 1);
    source(fd, "join-source-b", IP_ADD_SOURCE_MEMBERSHIP, 2);
    get(fd, "get-two-sources", 8);
    get(fd, "get-one-slot", 1);
    get(fd, "get-zero-slots", 0);
    source(fd, "block-include", IP_BLOCK_SOURCE, 3);
    source(fd, "drop-source-a", IP_DROP_SOURCE_MEMBERSHIP, 1);
    get(fd, "get-after-drop-a", 8);
    source(fd, "drop-last-source", IP_DROP_SOURCE_MEMBERSHIP, 2);
    get(fd, "get-after-last-drop", 8);
    member(fd, "asm-join", IP_ADD_MEMBERSHIP);
    source(fd, "block-source-a", IP_BLOCK_SOURCE, 1);
    source(fd, "block-source-a-again", IP_BLOCK_SOURCE, 1);
    get(fd, "get-exclude-a", 8);
    source(fd, "join-source-in-nonempty-exclude", IP_ADD_SOURCE_MEMBERSHIP, 2);
    source(fd, "unblock-source-a", IP_UNBLOCK_SOURCE, 1);
    get(fd, "get-exclude-empty", 8);
    source(fd, "join-source-in-empty-exclude", IP_ADD_SOURCE_MEMBERSHIP, 2);
    get(fd, "get-after-empty-mode-switch", 8);
    member(fd, "drop-group", IP_DROP_MEMBERSHIP);
    replace(fd, "replace-before-join", MCAST_EXCLUDE, 2, 0);
    member(fd, "asm-join-for-replace", IP_ADD_MEMBERSHIP);
    replace(fd, "replace-exclude-two", MCAST_EXCLUDE, 2, 0);
    get(fd, "get-replaced-exclude", 8);
    replace(fd, "replace-duplicate-sources", MCAST_EXCLUDE, 3, 1);
    get(fd, "get-duplicate-sources", 8);
    replace(fd, "replace-invalid-mode", 2, 1, 0);
    get(fd, "get-after-invalid-mode", 8);
    replace(fd, "replace-include-empty", MCAST_INCLUDE, 0, 0);
    get(fd, "get-after-empty-include", 8);
    close(fd);
    fd = open_socket(SOCK_DGRAM);
    for (unsigned at = 1; at <= 12; at++) {
        char label[64];
        snprintf(label, sizeof(label), "source-limit-%u", at);
        source(fd, label, IP_ADD_SOURCE_MEMBERSHIP, at);
    }
    get(fd, "get-source-limit", 16);
    close(fd);
    fd = open_socket(SOCK_DGRAM);
    member(fd, "bulk-join", IP_ADD_MEMBERSHIP);
    replace(fd, "bulk-eleven", MCAST_EXCLUDE, 11, 0);
    get(fd, "bulk-eleven-state", 16);
    replace(fd, "bulk-sixteen", MCAST_INCLUDE, 16, 0);
    get(fd, "bulk-sixteen-state", 16);
    replace(fd, "bulk-reset-exclude-empty", MCAST_EXCLUDE, 0, 0);
    source(fd, "add-source-after-explicit-empty-reset", IP_ADD_SOURCE_MEMBERSHIP, 1);
    get(fd, "get-after-explicit-empty-reset", 8);
    close(fd);
    fd = open_socket(SOCK_DGRAM);
    group_source(fd, "generic-block-before-join", MCAST_BLOCK_SOURCE, 1);
    group_source(fd, "generic-source-join-a", MCAST_JOIN_SOURCE_GROUP, 1);
    group_source(fd, "generic-source-join-b", MCAST_JOIN_SOURCE_GROUP, 2);
    get_group(fd, "generic-get-two", 8);
    get_group(fd, "generic-get-one-slot", 1);
    get_group(fd, "generic-get-zero-slots", 0);
    group_source(fd, "generic-duplicate-source", MCAST_JOIN_SOURCE_GROUP, 1);
    group_source(fd, "generic-drop-source-a", MCAST_LEAVE_SOURCE_GROUP, 1);
    group_source(fd, "generic-drop-source-b", MCAST_LEAVE_SOURCE_GROUP, 2);
    get_group(fd, "generic-after-last-drop", 8);
    probe_group_member(fd, "generic-asm-join", MCAST_JOIN_GROUP);
    group_source(fd, "generic-block-a", MCAST_BLOCK_SOURCE, 1);
    get_group(fd, "generic-exclude-a", 8);
    group_source(fd, "generic-unblock-a", MCAST_UNBLOCK_SOURCE, 1);
    probe_group_member(fd, "generic-group-leave", MCAST_LEAVE_GROUP);
    close(fd);
    fd = open_socket(SOCK_STREAM);
    probe_group_member(fd, "tcp-generic-asm", MCAST_JOIN_GROUP);
    group_source(fd, "tcp-generic-source", MCAST_JOIN_SOURCE_GROUP, 1);
    get_group(fd, "tcp-generic-filter", 8);
    close(fd);
    for (unsigned at = 0; at < 2; at++) {
        fd = open_socket(at ? SOCK_RAW : SOCK_STREAM);
        member(fd, at ? "raw-asm" : "tcp-asm", IP_ADD_MEMBERSHIP);
        source(fd, at ? "raw-source" : "tcp-source", IP_ADD_SOURCE_MEMBERSHIP, 1);
        get(fd, at ? "raw-filter" : "tcp-filter", 8);
        close(fd);
    }
    require(observed == sizeof(expected) / sizeof(expected[0]), "complete operation sequence");
    printf("IPV4 SOURCE FILTER ABI PASS cases=%u\n", observed);
    return 0;
}
