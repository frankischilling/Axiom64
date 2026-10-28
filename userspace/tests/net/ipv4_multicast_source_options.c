// SPDX-License-Identifier: GPL-3.0-or-later
/* Native Linux 6.6/6.17 observations fix the expectations. The same source
 * executes every operation in Axiom64; native setup alone owns a namespace. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

struct expectation {
    const char* name;
    int result, error;
    unsigned length, mode, count, family, first;
    int query;
};
static const struct expectation expected[] = {
    {"legacy-option-37-length-0", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-37-length-4", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-37-length-8", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-37-length-11", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-37-length-12", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-37-length-13", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-37-length-16", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-38-length-0", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-38-length-4", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-38-length-8", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-38-length-11", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-38-length-12", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-38-length-13", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-38-length-16", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-39-length-0", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-39-length-4", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-39-length-8", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-39-length-11", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-39-length-12", 0, 0, 0, 0, 0, 0, 0, 0},
    {"legacy-option-39-length-13", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-39-length-16", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-40-length-0", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-40-length-4", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-40-length-8", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-40-length-11", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-40-length-12", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-40-length-13", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-option-40-length-16", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-43-length-135", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-43-length-136", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-43-length-263", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-43-length-264", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-43-length-265", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-43-length-272", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-44-length-135", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-44-length-136", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-44-length-263", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-44-length-264", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-44-length-265", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-44-length-272", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-46-length-135", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-46-length-136", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-46-length-263", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-46-length-264", 0, 0, 0, 0, 0, 0, 0, 0},
    {"generic-option-46-length-265", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-46-length-272", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-47-length-135", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-47-length-136", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-47-length-263", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-47-length-264", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-47-length-265", -1, 22, 0, 0, 0, 0, 0, 0},
    {"generic-option-47-length-272", -1, 22, 0, 0, 0, 0, 0, 0},
    {"group-option-42-length-0", -1, 22, 0, 0, 0, 0, 0, 0},
    {"group-option-42-length-135", -1, 22, 0, 0, 0, 0, 0, 0},
    {"group-option-42-length-136", 0, 0, 0, 0, 0, 0, 0, 0},
    {"group-option-42-length-137", 0, 0, 0, 0, 0, 0, 0, 0},
    {"group-option-42-length-264", 0, 0, 0, 0, 0, 0, 0, 0},
    {"group-option-45-length-0", -1, 22, 0, 0, 0, 0, 0, 0},
    {"group-option-45-length-135", -1, 22, 0, 0, 0, 0, 0, 0},
    {"group-option-45-length-136", -1, 99, 0, 0, 0, 0, 0, 0},
    {"group-option-45-length-137", -1, 99, 0, 0, 0, 0, 0, 0},
    {"group-option-45-length-264", -1, 99, 0, 0, 0, 0, 0, 0},
    {"generic-source-wrong-group-family", -1, 99, 0, 0, 0, 0, 0, 0},
    {"generic-source-wrong-source-family", -1, 99, 0, 0, 0, 0, 0, 0},
    {"generic-join-wrong-family", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-source-foreign-interface", -1, 19, 0, 0, 0, 0, 0, 0},
    {"filter-0-count-1-prefix-only", -1, 22, 0, 0, 0, 0, 0, 0},
    {"filter-0-count-11-prefix-only", -1, 105, 0, 0, 0, 0, 0, 0},
    {"filter-0-count-4294967295-prefix-only", -1, 105, 0, 0, 0, 0, 0, 0},
    {"legacy-filter-wrong-mode", -1, 22, 0, 0, 0, 0, 0, 0},
    {"legacy-filter-null-prefix", -1, 14, 0, 0, 0, 0, 0, 0},
    {"legacy-filter-huge-null", -1, 105, 0, 0, 0, 0, 0, 0},
    {"get-0-length-0-count-8", -1, 22, 0, 2, 8, 0, 2779096485U, 1},
    {"get-0-length-15-count-8", -1, 22, 15, 2, 8, 0, 2779096485U, 1},
    {"get-0-length-16-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-19-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-20-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-24-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-143-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-144-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-145-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-272-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"get-0-length-528-count-8", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"legacy-get-count-zero", 0, 0, 16, 1, 3, 0, 2779096485U, 1},
    {"legacy-get-count-max", 0, 0, 28, 1, 3, 0, 3221225985U, 1},
    {"legacy-get-readonly-length", -1, 14, 16, 2, 8, 0, 2779096485U, 1},
    {"legacy-set-inaccessible-padding", -1, 14, 0, 0, 0, 0, 0, 0},
    {"filter-1-count-1-prefix-only", -1, 22, 0, 0, 0, 0, 0, 0},
    {"filter-1-count-11-prefix-only", -1, 105, 0, 0, 0, 0, 0, 0},
    {"filter-1-count-4294967295-prefix-only", -1, 105, 0, 0, 0, 0, 0, 0},
    {"generic-filter-wrong-family", -1, 99, 0, 0, 0, 0, 0, 0},
    {"generic-filter-null-prefix", -1, 14, 0, 0, 0, 0, 0, 0},
    {"generic-filter-huge-null", -1, 105, 0, 0, 0, 0, 0, 0},
    {"get-1-length-0-count-8", -1, 22, 0, 2, 8, 42405, 2779096485U, 1},
    {"get-1-length-15-count-8", -1, 22, 15, 2, 8, 42405, 2779096485U, 1},
    {"get-1-length-16-count-8", -1, 22, 16, 2, 8, 42405, 2779096485U, 1},
    {"get-1-length-19-count-8", -1, 22, 19, 2, 8, 42405, 2779096485U, 1},
    {"get-1-length-20-count-8", -1, 22, 20, 2, 8, 42405, 2779096485U, 1},
    {"get-1-length-24-count-8", -1, 22, 24, 2, 8, 42405, 2779096485U, 1},
    {"get-1-length-143-count-8", -1, 22, 143, 2, 8, 42405, 2779096485U, 1},
    {"get-1-length-144-count-8", 0, 0, 528, 1, 3, 2, 3221225985U, 1},
    {"get-1-length-145-count-8", 0, 0, 528, 1, 3, 2, 3221225985U, 1},
    {"get-1-length-272-count-8", 0, 0, 528, 1, 3, 2, 3221225985U, 1},
    {"get-1-length-528-count-8", 0, 0, 528, 1, 3, 2, 3221225985U, 1},
    {"generic-get-count-zero", 0, 0, 144, 1, 3, 42405, 2779096485U, 1},
    {"generic-get-count-max", 0, 0, 528, 1, 3, 2, 3221225985U, 1},
    {"generic-get-readonly-length", -1, 14, 144, 2, 8, 2, 3221225985U, 1},
    {"generic-set-inaccessible-padding", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-37-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-37-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-38-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-38-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-39-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-39-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-40-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-40-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-42-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-42-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-43-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-43-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-44-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-44-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-45-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-45-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-46-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-46-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-47-valid-length", -1, 92, 0, 0, 0, 0, 0, 0},
    {"unsupported-get-47-null-length", -1, 14, 0, 0, 0, 0, 0, 0},
};
static unsigned actual_index;
static unsigned operations;

static void need(int okay) {
    if (!okay) {
        perror("native source option probe");
        exit(2);
    }
}

static void check(const char* name, int code, int error, unsigned length, unsigned mode,
                  unsigned count, unsigned family, unsigned first, int query) {
    need(operations < sizeof(expected) / sizeof(expected[0]));
    const struct expectation* value = &expected[operations];
    if (strcmp(name, value->name) || code != value->result || error != value->error ||
        query != value->query ||
        (query && (length != value->length || mode != value->mode || count != value->count ||
                   family != value->family || first != value->first))) {
        fprintf(stderr, "FAIL source option operation=%s position=%u result=%d errno=%d\n", name,
                operations, code, error);
        exit(1);
    }
}

static int open_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    need(fd >= 0);
    return fd;
}

static void result(const char* name, int code) {
    int error = code < 0 ? errno : 0;
    printf("{\"operation\":\"%s\",\"returncode\":%d,\"errno\":%d}\n", name, code, error);
    check(name, code, error, 0, 0, 0, 0, 0, 0);
    operations++;
}

static void address(struct sockaddr_storage* destination, unsigned family, unsigned value) {
    struct sockaddr_in* a = (struct sockaddr_in*)destination;
    a->sin_family = family;
    a->sin_addr.s_addr = htonl(value);
}

static void request(unsigned char* bytes, int generic, unsigned count) {
    memset(bytes, 0, 1024);
    if (generic) {
        struct group_filter* value = (struct group_filter*)bytes;
        value->gf_interface = if_nametoindex("lo");
        address(&value->gf_group, AF_INET, 0xef7f2a01);
        value->gf_fmode = MCAST_INCLUDE;
        value->gf_numsrc = count;
        for (unsigned n = 0; n < count && n < 4; n++)
            address(&value->gf_slist[n], AF_INET, 0xc0000201 + n);
    } else {
        struct ip_msfilter* value = (struct ip_msfilter*)bytes;
        value->imsf_multiaddr.s_addr = htonl(0xef7f2a01);
        value->imsf_interface.s_addr = htonl(0x7f000001);
        value->imsf_fmode = MCAST_INCLUDE;
        value->imsf_numsrc = count;
        for (unsigned n = 0; n < count && n < 4; n++)
            value->imsf_slist[n].s_addr = htonl(0xc0000201 + n);
    }
}

static void join(int fd) {
    struct ip_mreq value = {0};
    value.imr_multiaddr.s_addr = htonl(0xef7f2a01);
    value.imr_interface.s_addr = htonl(0x7f000001);
    need(!setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &value, sizeof(value)));
}

static void set(int fd, const char* name, int option, const void* value, socklen_t length) {
    result(name, setsockopt(fd, IPPROTO_IP, option, value, length));
}

static void get(int fd, const char* name, int generic, unsigned count, socklen_t length,
                void* length_override) {
    union {
        uint64_t alignment;
        unsigned char bytes[1024];
    } storage;

    request(storage.bytes, generic, count);
    if (generic) {
        struct group_filter* value = (struct group_filter*)storage.bytes;
        value->gf_fmode = 2;
        memset(value->gf_slist, 0xa5, 512);
    } else {
        struct ip_msfilter* value = (struct ip_msfilter*)storage.bytes;
        value->imsf_fmode = 2;
        memset(value->imsf_slist, 0xa5, 64);
    }
    socklen_t* length_pointer = length_override ? length_override : &length;
    int code = getsockopt(fd, IPPROTO_IP, generic ? MCAST_MSFILTER : IP_MSFILTER, storage.bytes,
                          length_pointer);
    int error = code < 0 ? errno : 0;
    unsigned mode, actual, first, family = 0;
    if (generic) {
        struct group_filter* value = (struct group_filter*)storage.bytes;
        mode = value->gf_fmode;
        actual = value->gf_numsrc;
        struct sockaddr_in* a = (struct sockaddr_in*)&value->gf_slist[0];
        family = a->sin_family;
        first = ntohl(a->sin_addr.s_addr);
    } else {
        struct ip_msfilter* value = (struct ip_msfilter*)storage.bytes;
        mode = value->imsf_fmode;
        actual = value->imsf_numsrc;
        first = ntohl(value->imsf_slist[0].s_addr);
    }
    printf("{\"operation\":\"%s\",\"returncode\":%d,\"errno\":%d,\"length\":%u,\"mode\":%u,"
           "\"count\":%u,\"first_family\":%u,\"first_source\":%u}\n",
           name, code, error, *length_pointer, mode, actual, family, first);
    check(name, code, error, *length_pointer, mode, actual, family, first, 1);
    operations++;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    need(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")));
    if (argc == 2) {
        need(!unshare(CLONE_NEWNET));
        int control = open_socket();
        struct ifreq link = {0};
        strcpy(link.ifr_name, "lo");
        need(!ioctl(control, SIOCGIFFLAGS, &link));
        link.ifr_flags |= IFF_UP;
        need(!ioctl(control, SIOCSIFFLAGS, &link));
        close(control);
    }
    actual_index = if_nametoindex("lo");
    need(actual_index != 0);
    int fd;
    struct utsname kernel;
    need(!uname(&kernel));
    printf("{\"kernel\":\"%s\"}\n", kernel.release);

    union {
        uint64_t alignment;
        unsigned char bytes[1024];
    } storage;

    const unsigned legacy_lengths[] = {0, 4, 8, 11, 12, 13, 16};
    for (int option = IP_UNBLOCK_SOURCE; option <= IP_DROP_SOURCE_MEMBERSHIP; option++) {
        for (unsigned n = 0; n < sizeof(legacy_lengths) / sizeof(legacy_lengths[0]); n++) {
            fd = open_socket();
            memset(storage.bytes, 0, sizeof(storage.bytes));
            struct ip_mreq_source* value = (struct ip_mreq_source*)storage.bytes;
            value->imr_multiaddr.s_addr = htonl(0xef7f2a01);
            value->imr_interface.s_addr = htonl(0x7f000001);
            value->imr_sourceaddr.s_addr = htonl(0xc0000201);
            char label[64];
            snprintf(label, sizeof(label), "legacy-option-%d-length-%u", option, legacy_lengths[n]);
            set(fd, label, option, value, legacy_lengths[n]);
            close(fd);
        }
    }
    const unsigned generic_lengths[] = {135, 136, 263, 264, 265, 272};
    const int generic_options[] = {MCAST_BLOCK_SOURCE, MCAST_UNBLOCK_SOURCE,
                                   MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP};
    for (unsigned option = 0; option < 4; option++)
        for (unsigned n = 0; n < 6; n++) {
            fd = open_socket();
            memset(storage.bytes, 0, sizeof(storage.bytes));
            struct group_source_req* value = (struct group_source_req*)storage.bytes;
            value->gsr_interface = actual_index;
            address(&value->gsr_group, AF_INET, 0xef7f2a01);
            address(&value->gsr_source, AF_INET, 0xc0000201);
            char label[64];
            snprintf(label, sizeof(label), "generic-option-%d-length-%u", generic_options[option],
                     generic_lengths[n]);
            set(fd, label, generic_options[option], value, generic_lengths[n]);
            close(fd);
        }
    const unsigned group_lengths[] = {0, 135, 136, 137, 264};
    for (unsigned option = 0; option < 2; option++)
        for (unsigned n = 0; n < 5; n++) {
            fd = open_socket();
            memset(storage.bytes, 0, sizeof(storage.bytes));
            struct group_req* value = (struct group_req*)storage.bytes;
            value->gr_interface = actual_index;
            address(&value->gr_group, AF_INET, 0xef7f2a01);
            char label[64];
            snprintf(label, sizeof(label), "group-option-%u-length-%u",
                     option ? MCAST_LEAVE_GROUP : MCAST_JOIN_GROUP, group_lengths[n]);
            set(fd, label, option ? MCAST_LEAVE_GROUP : MCAST_JOIN_GROUP, value, group_lengths[n]);
            close(fd);
        }
    fd = open_socket();
    struct group_source_req gs = {0};
    gs.gsr_interface = actual_index;
    address(&gs.gsr_group, AF_INET6, 0xef7f2a01);
    address(&gs.gsr_source, AF_INET, 0xc0000201);
    set(fd, "generic-source-wrong-group-family", MCAST_JOIN_SOURCE_GROUP, &gs, sizeof(gs));
    address(&gs.gsr_group, AF_INET, 0xef7f2a01);
    address(&gs.gsr_source, AF_INET6, 0xc0000201);
    set(fd, "generic-source-wrong-source-family", MCAST_JOIN_SOURCE_GROUP, &gs, sizeof(gs));
    struct group_req gr = {0};
    gr.gr_interface = actual_index;
    address(&gr.gr_group, AF_INET6, 0xef7f2a01);
    set(fd, "generic-join-wrong-family", MCAST_JOIN_GROUP, &gr, sizeof(gr));
    struct ip_mreq_source ls = {0};
    ls.imr_multiaddr.s_addr = htonl(0xef7f2a01);
    ls.imr_interface.s_addr = htonl(0xc0000201);
    ls.imr_sourceaddr.s_addr = htonl(0xc0000201);
    set(fd, "legacy-source-foreign-interface", IP_ADD_SOURCE_MEMBERSHIP, &ls, sizeof(ls));
    close(fd);
    const unsigned counts[] = {1, 11, 0xffffffffU};
    for (int generic = 0; generic < 2; generic++) {
        unsigned prefix = generic ? 144 : 16;
        int option = generic ? MCAST_MSFILTER : IP_MSFILTER;
        fd = open_socket();
        for (unsigned n = 0; n < 3; n++) {
            request(storage.bytes, generic, counts[n]);
            char label[64];
            snprintf(label, sizeof(label), "filter-%d-count-%u-prefix-only", generic, counts[n]);
            set(fd, label, option, storage.bytes, prefix);
        }
        request(storage.bytes, generic, 0);
        if (generic)
            ((struct group_filter*)storage.bytes)->gf_group.ss_family = AF_INET6;
        else
            ((struct ip_msfilter*)storage.bytes)->imsf_fmode = 2;
        set(fd, generic ? "generic-filter-wrong-family" : "legacy-filter-wrong-mode", option,
            storage.bytes, prefix);
        set(fd, generic ? "generic-filter-null-prefix" : "legacy-filter-null-prefix", option, NULL,
            prefix);
        set(fd, generic ? "generic-filter-huge-null" : "legacy-filter-huge-null", option, NULL,
            16 * 1024 * 1024);
        join(fd);
        request(storage.bytes, generic, 3);
        need(!setsockopt(fd, IPPROTO_IP, option, storage.bytes, prefix + 3 * (generic ? 128 : 4)));
        const unsigned lengths[] = {0, 15, 16, 19, 20, 24, 143, 144, 145, 272, 528};
        for (unsigned n = 0; n < sizeof(lengths) / sizeof(lengths[0]); n++) {
            char label[64];
            snprintf(label, sizeof(label), "get-%d-length-%u-count-8", generic, lengths[n]);
            get(fd, label, generic, 8, lengths[n], NULL);
        }
        get(fd, generic ? "generic-get-count-zero" : "legacy-get-count-zero", generic, 0, prefix,
            NULL);
        get(fd, generic ? "generic-get-count-max" : "legacy-get-count-max", generic, 0xffffffffU,
            prefix, NULL);
        long page = sysconf(_SC_PAGESIZE);
        need(page > 0);
        void* memory =
            mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        need(memory != MAP_FAILED);
        socklen_t* readonly = memory;
        *readonly = prefix;
        need(!mprotect(memory, page, PROT_READ));
        get(fd, generic ? "generic-get-readonly-length" : "legacy-get-readonly-length", generic, 8,
            prefix, readonly);
        need(!mprotect(memory, page, PROT_READ | PROT_WRITE));
        unsigned char* tail = (unsigned char*)memory + page - prefix;
        request(storage.bytes, generic, 0);
        memcpy(tail, storage.bytes, prefix);
        need(!mprotect((unsigned char*)memory + page, page, PROT_NONE));
        set(fd, generic ? "generic-set-inaccessible-padding" : "legacy-set-inaccessible-padding",
            option, tail, prefix + 1);
        need(!munmap(memory, page * 2));
        close(fd);
    }
    fd = open_socket();
    for (int option = 37; option <= 48; option++)
        if (option != 41 && option != 48) {
            socklen_t length = 0;
            char label[64];
            snprintf(label, sizeof(label), "unsupported-get-%d-valid-length", option);
            result(label, getsockopt(fd, IPPROTO_IP, option, NULL, &length));
            snprintf(label, sizeof(label), "unsupported-get-%d-null-length", option);
            result(label, getsockopt(fd, IPPROTO_IP, option, NULL, NULL));
        }
    close(fd);
    need(operations == sizeof(expected) / sizeof(expected[0]));
    printf("IPV4 SOURCE OPTIONS PASS operations=%u\n", operations);
    return 0;
}
