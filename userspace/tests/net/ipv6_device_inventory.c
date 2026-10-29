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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned sequence, observations, queries;
static int control;
static const char* selected_action;
static unsigned selected_lane, selected_stage;

static void must(int condition) {
    if (!condition) {
        fprintf(stderr, "LINK_STATE_FATAL errno=%d\n", errno);
        exit(90);
    }
}

static void scalar(const char* scope, const char* property, const char* value) {
    char path[160];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", scope, property);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    must(fd >= 0 && write(fd, value, strlen(value)) == (ssize_t)strlen(value));
    must(!close(fd));
}

static void raw_record(const char* kind, unsigned transaction, unsigned datagram, const void* data,
                       size_t size) {
    static const char hex[] = "0123456789abcdef";
    char* text = malloc(2 * size + 160);
    must(text != NULL);
    int at = snprintf(text, 160, "LINK_RAW kind=%s sequence=%u datagram=%u bytes=%zu hex=", kind,
                      transaction, datagram, size);
    must(at > 0 && at < 160);
    const unsigned char* bytes = data;
    for (size_t i = 0; i < size; i++) {
        text[at++] = hex[bytes[i] >> 4];
        text[at++] = hex[bytes[i] & 15];
    }
    text[at++] = '\n';
    must(write(STDOUT_FILENO, text, at) == at);
    free(text);
}

static void generation(const void* bytes, int length, int* found, int* mode) {
    for (struct rtattr* item = (void*)bytes; RTA_OK(item, length); item = RTA_NEXT(item, length)) {
        if ((item->rta_type & NLA_TYPE_MASK) == IFLA_INET6_ADDR_GEN_MODE) {
            must(RTA_PAYLOAD(item) == 1 && !(*found)++);
            *mode = *(unsigned char*)RTA_DATA(item);
        }
    }
    must(length == 0);
}

static void query(unsigned index, unsigned family, int dump) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    must(fd >= 0);
    struct sockaddr_nl local = {.nl_family = AF_NETLINK}, kernel = {.nl_family = AF_NETLINK};
    must(!bind(fd, (void*)&local, sizeof(local)));
    socklen_t size = sizeof(local);
    must(!getsockname(fd, (void*)&local, &size) && size == sizeof(local));

    struct {
        struct nlmsghdr header;
        struct ifinfomsg link;
    } request = {.header = {.nlmsg_len = sizeof(request),
                            .nlmsg_type = RTM_GETLINK,
                            .nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0),
                            .nlmsg_seq = ++sequence},
                 .link = {.ifi_family = family, .ifi_index = dump ? 0 : (int)index}};

    raw_record("request", sequence, 0, &request, sizeof(request));
    must(sendto(fd, &request, sizeof(request), 0, (void*)&kernel, sizeof(kernel)) ==
         sizeof(request));
    int finished = 0, error = 0, found = 0, mode_found = 0, mode = -1, done = 0;
    unsigned flags = 0, mtu = 0, datagrams = 0, messages = 0;
    while (!finished) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        must(poll(&ready, 1, 3000) == 1 && (ready.revents & POLLIN));
        _Alignas(struct nlmsghdr) unsigned char buffer[16384];
        int remaining = recv(fd, buffer, sizeof(buffer), 0);
        must(remaining > 0 && remaining < (int)sizeof(buffer) && datagrams < 16);
        raw_record("reply", sequence, datagrams++, buffer, remaining);
        for (struct nlmsghdr* header = (void*)buffer; NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            must(++messages <= 64 && header->nlmsg_seq == sequence &&
                 header->nlmsg_pid == local.nl_pid && !(header->nlmsg_flags & NLM_F_DUMP_INTR));
            if (header->nlmsg_type == NLMSG_ERROR) {
                must(header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)));
                error = ((struct nlmsgerr*)NLMSG_DATA(header))->error;
                must(error < 0);
                finished = 1;
            } else if (header->nlmsg_type == NLMSG_DONE) {
                must(dump && header->nlmsg_len >= NLMSG_LENGTH(sizeof(int)));
                memcpy(&error, NLMSG_DATA(header), sizeof(error));
                must(!error);
                done++;
                finished = 1;
            } else {
                must(header->nlmsg_type == RTM_NEWLINK &&
                     header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg)));
                struct ifinfomsg* link = NLMSG_DATA(header);
                if ((unsigned)link->ifi_index == index) {
                    must(!found++);
                    flags = link->ifi_flags;
                    int length = IFLA_PAYLOAD(header);
                    for (struct rtattr* item = IFLA_RTA(link); RTA_OK(item, length);
                         item = RTA_NEXT(item, length)) {
                        unsigned type = item->rta_type & NLA_TYPE_MASK;
                        if (type == IFLA_MTU) {
                            must(RTA_PAYLOAD(item) == sizeof(mtu));
                            memcpy(&mtu, RTA_DATA(item), sizeof(mtu));
                        } else if (type == IFLA_PROTINFO && link->ifi_family == AF_INET6)
                            generation(RTA_DATA(item), RTA_PAYLOAD(item), &mode_found, &mode);
                        else if (type == IFLA_AF_SPEC) {
                            int left = RTA_PAYLOAD(item);
                            for (struct rtattr* af = RTA_DATA(item); RTA_OK(af, left);
                                 af = RTA_NEXT(af, left))
                                if ((af->rta_type & NLA_TYPE_MASK) == AF_INET6)
                                    generation(RTA_DATA(af), RTA_PAYLOAD(af), &mode_found, &mode);
                            must(left == 0);
                        }
                    }
                    must(length == 0);
                }
                if (!dump)
                    finished = 1;
            }
        }
        must(remaining == 0);
    }
    must(!close(fd));
    printf("LINK_QUERY action=%s lane=%u stage=%u family=%u dump=%d error=%d found=%d flags=%x "
           "mtu=%u mode_found=%d mode=%d done=%d datagrams=%u sequence=%u\n",
           selected_action, selected_lane, selected_stage, family, dump, error, found, flags, mtu,
           mode_found, mode, done, datagrams, sequence);
    queries++;
}

static void snapshot(void) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", selected_lane);
    must(!ioctl(control, SIOCGIFINDEX, &request));
    unsigned index = request.ifr_ifindex;
    // An ordinary link query synchronizes pending carrier work on Linux.
    // Observe ioctl flags after that barrier, retaining all four raw queries.
    query(index, AF_UNSPEC, 0);
    must(!ioctl(control, SIOCGIFFLAGS, &request));
    unsigned flags = (unsigned short)request.ifr_flags;
    must(!ioctl(control, SIOCGIFMTU, &request));
    unsigned mtu = request.ifr_mtu;
    char path[160], bytes[32];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/eth%u/addr_gen_mode", selected_lane);
    int fd = open(path, O_RDONLY | O_CLOEXEC), mode = -1, present = fd >= 0;
    if (fd >= 0) {
        ssize_t length = read(fd, bytes, sizeof(bytes) - 1);
        must(length > 0 && !close(fd));
        bytes[length] = 0;
        mode = atoi(bytes);
    } else
        must(errno == ENOENT);
    printf("LINK_STATE action=%s lane=%u stage=%u flags=%x mtu=%u proc=%d mode=%d\n",
           selected_action, selected_lane, selected_stage, flags, mtu, present, mode);
    for (unsigned family = 0; family <= 10; family += 10)
        for (int dump = 0; dump < 2; dump++)
            if (family != AF_UNSPEC || dump)
                query(index, family, dump);
    observations++;
}

static void change(int restore) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", selected_lane);
    if (!strcmp(selected_action, "administrative")) {
        must(!ioctl(control, SIOCGIFFLAGS, &request));
        request.ifr_flags = restore ? request.ifr_flags | IFF_UP : request.ifr_flags & ~IFF_UP;
        must(!ioctl(control, SIOCSIFFLAGS, &request));
    } else {
        request.ifr_mtu = restore ? 1500 : 1279;
        must(!ioctl(control, SIOCSIFMTU, &request));
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    scalar("all", "disable_ipv6", "1\n");
    scalar("default", "disable_ipv6", "1\n");
    scalar("default", "addr_gen_mode", "1\n");
    control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    must(control >= 0);
    for (selected_lane = 0; selected_lane < 2; selected_lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", selected_lane);
        must(!ioctl(control, SIOCGIFFLAGS, &request));
        request.ifr_flags |= IFF_UP;
        must(!ioctl(control, SIOCSIFFLAGS, &request));
    }
    for (unsigned action = 0; action < 2; action++) {
        selected_action = action ? "mtu" : "administrative";
        for (selected_lane = 0; selected_lane < 2; selected_lane++) {
            char scope[16];
            snprintf(scope, sizeof(scope), "eth%u", selected_lane);
            scalar(scope, "stable_secret", "fd00::10\n");
            scalar(scope, "addr_gen_mode", "2\n");
            selected_stage = 0;
            snapshot();
            change(0);
            selected_stage = 1;
            snapshot();
            change(1);
            selected_stage = 2;
            snapshot();
        }
    }
    must(!close(control));
    printf("LINK_STATE_COMPLETE observations=%u queries=%u\n", observations, queries);
    return 0;
}
