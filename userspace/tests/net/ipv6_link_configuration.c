// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned sequence, records;

static void must(int condition) {
    if (!condition) {
        fprintf(stderr, "LINK_IO_FATAL errno=%d\n", errno);
        exit(90);
    }
}

static int setting(const char* interface, const char* name, const char* value) {
    char path[256], text[64];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", interface, name);
    int fd = open(path, (value ? O_WRONLY : O_RDONLY) | O_CLOEXEC);
    must(fd >= 0);
    ssize_t size = value ? write(fd, value, strlen(value)) : read(fd, text, sizeof(text) - 1);
    must(size > 0 && (!value || size == (ssize_t)strlen(value)));
    must(close(fd) == 0);
    if (value)
        return 0;
    text[size] = 0;
    return atoi(text);
}

static size_t attribute(unsigned char* bytes, size_t at, unsigned type, const void* value,
                        size_t size) {
    struct rtattr field = {.rta_len = RTA_LENGTH(size), .rta_type = type};
    memcpy(bytes + at, &field, sizeof(field));
    if (size)
        memcpy(bytes + at + sizeof(field), value, size);
    return at + RTA_SPACE(size);
}

static int transact(unsigned char* bytes, size_t length, unsigned type, int* mode) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    must(fd >= 0);
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    must(bind(fd, (struct sockaddr*)&local, sizeof(local)) == 0);
    socklen_t capacity = sizeof(local);
    must(getsockname(fd, (struct sockaddr*)&local, &capacity) == 0 && capacity == sizeof(local));
    struct nlmsghdr header = {.nlmsg_len = length,
                              .nlmsg_type = type,
                              .nlmsg_flags = NLM_F_REQUEST | (mode ? 0 : NLM_F_ACK),
                              .nlmsg_seq = ++sequence};
    memcpy(bytes, &header, sizeof(header));
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    must(sendto(fd, bytes, length, 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
         (ssize_t)length);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    must(poll(&ready, 1, 3000) == 1 && (ready.revents & POLLIN));
    unsigned char reply[8192];
    int remaining = recv(fd, reply, sizeof(reply), 0), result = -EPROTO, found = 0;
    must(remaining > 0 && remaining < (int)sizeof(reply));
    for (struct nlmsghdr* message = (void*)reply; NLMSG_OK(message, remaining);
         message = NLMSG_NEXT(message, remaining)) {
        must(message->nlmsg_seq == sequence && message->nlmsg_pid == local.nl_pid);
        if (message->nlmsg_type == NLMSG_ERROR) {
            must(message->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)));
            result = ((struct nlmsgerr*)NLMSG_DATA(message))->error;
            found++;
            continue;
        }
        must(mode && message->nlmsg_type == RTM_NEWLINK &&
             message->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg)));
        struct ifinfomsg* link = NLMSG_DATA(message);
        struct ifinfomsg requested;
        memcpy(&requested, bytes + NLMSG_HDRLEN, sizeof(requested));
        must(link->ifi_index == requested.ifi_index && link->ifi_family == AF_UNSPEC &&
             !(message->nlmsg_flags & NLM_F_MULTI));
        int left = IFLA_PAYLOAD(message);
        for (struct rtattr* field = IFLA_RTA(link); RTA_OK(field, left);
             field = RTA_NEXT(field, left)) {
            if ((field->rta_type & NLA_TYPE_MASK) != IFLA_AF_SPEC)
                continue;
            int families = RTA_PAYLOAD(field);
            for (struct rtattr* family = RTA_DATA(field); RTA_OK(family, families);
                 family = RTA_NEXT(family, families)) {
                if ((family->rta_type & NLA_TYPE_MASK) != AF_INET6)
                    continue;
                int items = RTA_PAYLOAD(family);
                for (struct rtattr* item = RTA_DATA(family); RTA_OK(item, items);
                     item = RTA_NEXT(item, items)) {
                    if ((item->rta_type & NLA_TYPE_MASK) == IFLA_INET6_ADDR_GEN_MODE) {
                        must(RTA_PAYLOAD(item) == 1);
                        *mode = *(unsigned char*)RTA_DATA(item);
                        result = 0;
                        found++;
                    }
                }
                must(items == 0);
            }
            must(families == 0);
        }
        must(left == 0);
    }
    must(remaining == 0 && found == 1 && close(fd) == 0);
    return result;
}

static int query(unsigned index, unsigned family, int* mode) {
    unsigned char bytes[32] = {0};
    struct ifinfomsg* link = (void*)(bytes + NLMSG_HDRLEN);
    link->ifi_index = index;
    link->ifi_family = family;
    return transact(bytes, sizeof(bytes), RTM_GETLINK, mode);
}

static int change(unsigned index, unsigned mode, unsigned length, unsigned shape, int nested,
                  unsigned family) {
    unsigned char bytes[256] = {0}, inet[64] = {0}, families[80] = {0};
    struct ifinfomsg* link = (void*)(bytes + NLMSG_HDRLEN);
    link->ifi_index = index;
    link->ifi_family = family;
    unsigned char value[4] = {mode, 0x5a, 0xa5, 0x7e};
    size_t at = 0;
    if (!shape || shape == 3)
        at = attribute(inet, at, IFLA_INET6_ADDR_GEN_MODE, value, length);
    if (shape == 1 || shape == 3) {
        int conf = 2;
        at = attribute(inet, at, IFLA_INET6_CONF, &conf, sizeof(conf));
    }
    if (shape == 4)
        at = attribute(inet, at, 99, value, 1);
    size_t size = attribute(families, 0, AF_INET6 | (nested ? NLA_F_NESTED : 0), inet, at);
    size = attribute(bytes, NLMSG_LENGTH(sizeof(*link)), IFLA_AF_SPEC | (nested ? NLA_F_NESTED : 0),
                     families, size);
    return transact(bytes, size, RTM_NEWLINK, NULL);
}

static void sample(const char* label, unsigned lane, unsigned index, int result) {
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    int mode = -1, inet6 = -1;
    int queried = query(index, AF_UNSPEC, &mode), queried6 = query(index, AF_INET6, &inet6);
    printf("LINK_IO label=%s lane=%u uid=%u result=%d mode=%d query=%d observed=%d query6=%d "
           "observed6=%d\n",
           label, lane, (unsigned)getuid(), result, setting(name, "addr_gen_mode", NULL), queried,
           mode, queried6, inet6);
    records++;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    must(setting("all", "addr_gen_mode", "1") == 0);
    unsigned indices[2] = {if_nametoindex("eth0"), if_nametoindex("eth1")};
    must(indices[0] && indices[1] && indices[0] != indices[1]);
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned index = indices[lane];
        sample("initial", lane, index, 0);
        sample("eui64", lane, index, change(index, 0, 1, 0, 1, AF_UNSPEC));
        sample("none", lane, index, change(index, 1, 1, 0, 1, AF_UNSPEC));
        sample("invalid4", lane, index, change(index, 4, 1, 0, 1, AF_UNSPEC));
        sample("invalid255", lane, index, change(index, 255, 1, 0, 1, AF_UNSPEC));
        sample("stable-without-secret", lane, index, change(index, 2, 1, 0, 1, AF_UNSPEC));
        sample("empty-value", lane, index, change(index, 0, 0, 0, 1, AF_UNSPEC));
        sample("two-bytes", lane, index, change(index, 0, 2, 0, 1, AF_UNSPEC));
        sample("four-bytes", lane, index, change(index, 1, 4, 0, 1, AF_UNSPEC));
        sample("empty-family", lane, index, change(index, 0, 1, 2, 1, AF_UNSPEC));
        sample("conf-only", lane, index, change(index, 0, 1, 1, 1, AF_UNSPEC));
        sample("unknown-only", lane, index, change(index, 0, 1, 4, 1, AF_UNSPEC));
        sample("with-conf", lane, index, change(index, 0, 1, 3, 1, AF_UNSPEC));
        sample("without-nested", lane, index, change(index, 1, 1, 0, 0, AF_UNSPEC));
        sample("inet6-family", lane, index, change(index, 0, 1, 0, 1, AF_INET6));
        sample("missing-interface", lane, index, change(999, 1, 1, 0, 1, AF_UNSPEC));
        sample("random", lane, index, change(index, 3, 1, 0, 1, AF_UNSPEC));
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        must(setting(name, "stable_secret", "2001:db8::1234") == 0);
        sample("stable-with-secret", lane, index, change(index, 2, 1, 0, 1, AF_UNSPEC));
        sample("retire", lane, index, change(index, 1, 1, 0, 1, AF_UNSPEC));
    }
    pid_t child = fork();
    must(child >= 0);
    if (!child) {
        must(setuid(65534) == 0);
        sample("ordinary", 0, indices[0], change(indices[0], 0, 1, 0, 1, AF_UNSPEC));
        _exit(0);
    }
    int status;
    must(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("LINK_IO_COMPLETE parent=%u child=1\n", records);
    return 0;
}
