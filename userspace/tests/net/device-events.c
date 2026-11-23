// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/device-events.c
 * @brief   Verify device-event sockets against the PCI inventory.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "DEVICE_EVENTS_FAIL line=%d errno=%d %s\n", __LINE__, errno, #expr);   \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static int listener(int protocol, int type, uint32_t port, uint32_t groups) {
    int fd = socket(AF_NETLINK, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
    CHECK(fd >= 0);
    struct sockaddr_nl address = {.nl_family = AF_NETLINK, .nl_pid = port, .nl_groups = groups};
    CHECK(bind(fd, (struct sockaddr*)&address, sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    CHECK(getsockname(fd, (struct sockaddr*)&address, &length) == 0);
    CHECK(length == sizeof(address) && address.nl_family == AF_NETLINK && address.nl_pid &&
          (!port || address.nl_pid == port) && address.nl_groups == groups);
    return fd;
}

static void set_filter(int fd) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xffffff00),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x63686100, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog program = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == 0);
    code[2].jf = UINT8_MAX;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == -1 &&
          errno == EINVAL);
}

static size_t receive_from(int fd, char* payload, size_t capacity, int flags, uint32_t port,
                           uint32_t groups, pid_t sender) {
    struct sockaddr_nl source;
    struct iovec buffer = {.iov_base = payload, .iov_len = capacity};
    _Alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr message = {.msg_name = &source,
                             .msg_namelen = sizeof(source),
                             .msg_iov = &buffer,
                             .msg_iovlen = 1,
                             .msg_control = control,
                             .msg_controllen = sizeof(control)};
    ssize_t length = recvmsg(fd, &message, flags);
    CHECK(length > 0 && (size_t)length <= capacity && !(message.msg_flags & MSG_CTRUNC));
    CHECK(message.msg_namelen == sizeof(source) && source.nl_family == AF_NETLINK &&
          source.nl_pid == port && source.nl_groups == groups);
    struct cmsghdr* header = CMSG_FIRSTHDR(&message);
    CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_CREDENTIALS &&
          header->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
    struct ucred identity;
    memcpy(&identity, CMSG_DATA(header), sizeof(identity));
    CHECK(identity.pid == sender && identity.uid == 0 && identity.gid == 0);
    return length;
}

static size_t receive(int fd, char* payload, size_t capacity, int flags) {
    return receive_from(fd, payload, capacity, flags, 0, 1, 0);
}

static const char* property(const char* payload, size_t length, const char* name) {
    size_t prefix = strlen(name);
    for (size_t offset = strlen(payload) + 1; offset < length;) {
        const char* item = payload + offset;
        const char* end = memchr(item, 0, length - offset);
        CHECK(end);
        if ((size_t)(end - item) > prefix && !memcmp(item, name, prefix))
            return item + prefix;
        offset = end - payload + 1;
    }
    return NULL;
}

int main(void) {
    glob_t devices;
    CHECK(glob("/sys/bus/pci/devices/*/uevent", 0, NULL, &devices) == 0);
    CHECK(devices.gl_pathc > 0);
    const char* path = devices.gl_pathv[0];
    char* canonical = realpath(path, NULL);
    CHECK(canonical && !strncmp(canonical, "/sys/devices/", sizeof("/sys/devices/") - 1));
    *strrchr(canonical, '/') = 0;
    int trigger = open(path, O_RDWR | O_CLOEXEC);
    CHECK(trigger >= 0);
    char attrs[1024];
    ssize_t size = read(trigger, attrs, sizeof(attrs) - 1);
    CHECK(size > 0 && size < (ssize_t)sizeof(attrs));
    attrs[size] = 0;
    CHECK(strstr(attrs, "SUBSYSTEM=pci\n") && strstr(attrs, "\nPCI_ID="));
    CHECK(write(trigger, "ACTION=add\n", 11) == -1 && errno == EINVAL);
    CHECK(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, trigger, 0) == MAP_FAILED &&
          errno == ENODEV);

    int route = listener(NETLINK_ROUTE, SOCK_RAW, getpid(), 0);
    int monitor = listener(NETLINK_KOBJECT_UEVENT, SOCK_DGRAM, getpid(), 1);
    int quiet = listener(NETLINK_KOBJECT_UEVENT, SOCK_RAW, 0, 0);
    int relay = listener(NETLINK_KOBJECT_UEVENT, SOCK_RAW, 0, 0);
    int group = 2;
    CHECK(setsockopt(relay, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) == 0);
    const struct sockaddr_nl receiver = {.nl_family = AF_NETLINK, .nl_groups = 2};
    const char message[] = "change relay";
    int option = 0;
    socklen_t option_length = sizeof(option);
    CHECK(getsockopt(monitor, SOL_SOCKET, SO_PROTOCOL, &option, &option_length) == 0 &&
          option == NETLINK_KOBJECT_UEVENT);
    option = 1;
    CHECK(setsockopt(monitor, SOL_SOCKET, SO_PASSCRED, &option, sizeof(option)) == 0);
    CHECK(setsockopt(relay, SOL_SOCKET, SO_PASSCRED, &option, sizeof(option)) == 0);
    set_filter(monitor);
    set_filter(quiet);
    CHECK(write(trigger, "add\n", 4) == 4);
    char data[2048];
    CHECK(recv(monitor, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    CHECK(send(monitor, "change", 6, 0) == -1 && errno == EOPNOTSUPP);
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK, .nl_groups = 1};
    CHECK(sendto(monitor, message, sizeof(message), 0, (const struct sockaddr*)&kernel,
                 sizeof(kernel)) == -1 &&
          errno == EOPNOTSUPP);

    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event watch = {.events = EPOLLIN | EPOLLET, .data.fd = monitor};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, monitor, &watch) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(usleep(200000) == 0);
        CHECK(write(trigger, "change\n", 7) == 7);
        CHECK(setgid(65534) == 0 && setuid(65534) == 0);
        CHECK(open(path, O_WRONLY) == -1 && errno == EACCES);
        CHECK(write(trigger, "change\n", 7) == -1 && errno == EPERM);
        CHECK(sendto(monitor, message, sizeof(message), 0, (const struct sockaddr*)&receiver,
                     sizeof(receiver)) == -1 &&
              errno == EPERM);
        _Exit(0);
    }
    struct epoll_event event;
    CHECK(epoll_wait(epoll, &event, 1, 3000) == 1 && event.data.fd == monitor &&
          (event.events & EPOLLIN));
    size_t length = receive(monitor, data, sizeof(data), MSG_PEEK);
    CHECK(data[length - 1] == 0 && !strncmp(data, "change@", 7));
    CHECK(!strcmp(data + 7, canonical + 4));
    const char* action = property(data, length, "ACTION=");
    const char* subsystem = property(data, length, "SUBSYSTEM=");
    const char* devpath = property(data, length, "DEVPATH=");
    const char* id = property(data, length, "PCI_ID=");
    const char* seqnum = property(data, length, "SEQNUM=");
    CHECK(action && !strcmp(action, "change") && subsystem && !strcmp(subsystem, "pci"));
    CHECK(devpath && !strcmp(devpath, canonical + 4) && id && strlen(id) == 9 && id[4] == ':');
    CHECK(seqnum && strtoull(seqnum, NULL, 10) > 0);
    unsigned long long sequence = strtoull(seqnum, NULL, 10);
    char copy[2048];
    CHECK(receive(monitor, copy, sizeof(copy), 0) == length && !memcmp(copy, data, length));
    CHECK(recv(monitor, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    CHECK(recv(quiet, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    CHECK(recv(route, data, sizeof(data), 0) == -1 && errno == EAGAIN);

    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(recv(relay, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    CHECK(sendto(monitor, message, sizeof(message), 0, (const struct sockaddr*)&receiver,
                 sizeof(receiver)) == sizeof(message));
    CHECK(receive_from(relay, data, sizeof(data), 0, getpid(), 2, getpid()) == sizeof(message));
    CHECK(!memcmp(data, message, sizeof(message)));
    CHECK(recv(monitor, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    CHECK(setsockopt(relay, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, &group, sizeof(group)) == 0);
    CHECK(sendto(monitor, message, sizeof(message), 0, (const struct sockaddr*)&receiver,
                 sizeof(receiver)) == sizeof(message));
    CHECK(recv(relay, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    for (unsigned i = 0; i < 33; ++i)
        CHECK(write(trigger, "change\n", 7) == 7);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && (event.events & EPOLLERR));
    CHECK(recv(monitor, data, sizeof(data), 0) == -1 && errno == ENOBUFS);
    for (unsigned i = 0; i < 32; ++i) {
        length = receive(monitor, data, sizeof(data), 0);
        CHECK(data[length - 1] == 0);
        seqnum = property(data, length, "SEQNUM=");
        CHECK(seqnum && strtoull(seqnum, NULL, 10) == ++sequence);
    }
    CHECK(recv(monitor, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    CHECK(setsockopt(monitor, SOL_SOCKET, SO_DETACH_FILTER, &option, sizeof(option)) == 0);
    CHECK(write(trigger, "add\n", 4) == 4);
    CHECK(receive(monitor, data, sizeof(data), 0) > 0 && !strncmp(data, "add@", 4));
    free(canonical);
    globfree(&devices);
    puts("DEVICE_EVENTS_PASS");
    return 0;
}
