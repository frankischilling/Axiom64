// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/boot-media.c
 * @brief   Read the boot module from the first userspace process.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Reports a token read from the initramfs, then shuts down the guest.
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
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static int check_input_inventory(void) {
    for (unsigned i = 0; i < 2; ++i) {
        char dev[64], link[64], target[64], attr[96], received[32];
        struct stat dev_stat, class_stat, char_stat;
        snprintf(dev, sizeof(dev), "/dev/input/event%u", i);
        if (stat(dev, &dev_stat) || !S_ISCHR(dev_stat.st_mode) || major(dev_stat.st_rdev) != 13 ||
            minor(dev_stat.st_rdev) != 64 + i)
            return -1;
        snprintf(link, sizeof(link), "/sys/dev/char/13:%u", minor(dev_stat.st_rdev));
        ssize_t length = readlink(link, target, sizeof(target) - 1);
        if (length <= 0)
            return -1;
        target[length] = 0;
        snprintf(attr, sizeof(attr), "../../devices/virtual/input/input%u/event%u", i, i);
        if (strcmp(target, attr) || stat(link, &char_stat))
            return -1;
        snprintf(link, sizeof(link), "/sys/class/input/event%u", i);
        if (stat(link, &class_stat) || class_stat.st_ino != char_stat.st_ino)
            return -1;
        snprintf(attr, sizeof(attr), "%s/device/capabilities/rel", link);
        int fd = open(attr, O_RDONLY);
        if (fd < 0)
            return -1;
        const char* expected = i ? "103\n" : "0\n";
        length = read(fd, received, sizeof(received));
        if (close(fd) || length != (ssize_t)strlen(expected) || memcmp(received, expected, length))
            return -1;
    }
    puts("BOOT_INPUT_INVENTORY_PASS");
    return 0;
}

static int check_input_uevent(void) {
    struct netlink_address {
        uint16_t family, padding;
        uint32_t port, groups;
    } local = {AF_NETLINK, 0, 0x13579, 1}, sender = {0};

    enum { kernel_uevent = 15, so_passcred = 16, scm_credentials = 2 };

    const int listener = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, kernel_uevent);
    const int route = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, 0);
    if (listener < 0 || route < 0 || bind(listener, (struct sockaddr*)&local, sizeof(local)))
        return -1;
    socklen_t length = sizeof(local);
    if (getsockname(listener, (struct sockaddr*)&local, &length) || length != sizeof(local) ||
        local.port != 0x13579 || local.groups != 1)
        return -1;
    local.groups = 0;
    int enabled = 1;
    if (bind(route, (struct sockaddr*)&local, sizeof(local)) ||
        setsockopt(listener, SOL_SOCKET, so_passcred, &enabled, sizeof(enabled)))
        return -1;

    const int trigger = open("/sys/class/input/event1/uevent", O_WRONLY | O_TRUNC);
    if (trigger < 0 || write(trigger, "bogus", 5) != -1 || errno != EINVAL ||
        write(trigger, "add\n", 4) != 4 || close(trigger))
        return -1;

    struct pollfd ready[] = {{listener, POLLIN, 0}, {route, POLLIN, 0}};
    if (poll(ready, 2, 100) != 1 || !(ready[0].revents & POLLIN) || ready[1].revents)
        return -1;
    char data[256];
    struct iovec payload = {data, sizeof(data)};

    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(uint32_t) * 3)];
    } ancillary;
    struct msghdr message = {0};
    message.msg_name = &sender;
    message.msg_namelen = sizeof(sender);
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    const ssize_t bytes = recvmsg(listener, &message, 0);
    const struct cmsghdr* info = CMSG_FIRSTHDR(&message);
    if (bytes < 1 || message.msg_flags || message.msg_namelen != sizeof(sender) ||
        sender.family != AF_NETLINK || sender.port != 0 || sender.groups != 1 || !info ||
        info->cmsg_level != SOL_SOCKET || info->cmsg_type != scm_credentials ||
        info->cmsg_len != CMSG_LEN(sizeof(uint32_t) * 3))
        return -1;
    const uint32_t expected[3] = {0};
    if (memcmp(CMSG_DATA(info), expected, sizeof(expected)))
        return -1;
    const char prefix[] = "add@/devices/virtual/input/input1/event1\0ACTION=add\0"
                          "DEVPATH=/devices/virtual/input/input1/event1\0SUBSYSTEM=input\0"
                          "MAJOR=13\0MINOR=65\0DEVNAME=input/event1\0SYNTH_UUID=0\0SEQNUM=";
    if (bytes <= (ssize_t)sizeof(prefix) || data[bytes - 1] ||
        memcmp(data, prefix, sizeof(prefix) - 1))
        return -1;
    for (size_t i = sizeof(prefix) - 1; i < (size_t)bytes - 1; ++i)
        if (data[i] < '0' || data[i] > '9')
            return -1;
    if (send(listener, prefix, sizeof(prefix), 0) != -1 || errno != EOPNOTSUPP)
        return -1;

    const int relay = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, kernel_uevent);
    struct netlink_address processed = {AF_NETLINK, 0, 0, 2};
    int joining = 2;
    if (relay < 0 || bind(relay, (struct sockaddr*)&processed, sizeof(processed)) ||
        setsockopt(relay, SOL_SOCKET, so_passcred, &enabled, sizeof(enabled)) ||
        setsockopt(relay, 270, 1, &joining, sizeof(joining)))
        return -1;
    socklen_t processed_length = sizeof(processed);
    if (getsockname(relay, (struct sockaddr*)&processed, &processed_length) ||
        processed.port == local.port || !processed.port || processed.groups != 2)
        return -1;

    // A named send uses the transport address, but credentials identify the
    // process even when the socket is bound to a different port.
    struct netlink_address destination = {AF_NETLINK, 0, 0, 2};
    const char event[] = "processed input";
    if (sendto(listener, event, sizeof(event), 0, (struct sockaddr*)&destination,
               sizeof(destination)) != sizeof(event))
        return -1;
    message.msg_namelen = sizeof(sender);
    message.msg_controllen = sizeof(ancillary.bytes);
    if (recvmsg(relay, &message, 0) != sizeof(event) || memcmp(data, event, sizeof(event)) ||
        sender.port != local.port || sender.groups != 2)
        return -1;
    info = CMSG_FIRSTHDR(&message);
    const uint32_t relay_credentials[] = {(uint32_t)getpid(), (uint32_t)getuid(),
                                          (uint32_t)getgid()};
    if (!info || info->cmsg_type != scm_credentials ||
        memcmp(CMSG_DATA(info), relay_credentials, sizeof(relay_credentials)))
        return -1;

    destination.port = processed.port;
    destination.groups = 0;
    if (connect(listener, (struct sockaddr*)&destination, sizeof(destination)) ||
        send(listener, event, sizeof(event), 0) != sizeof(event))
        return -1;
    message.msg_namelen = sizeof(sender);
    message.msg_controllen = sizeof(ancillary.bytes);
    if (recvmsg(relay, &message, 0) != sizeof(event) || memcmp(data, event, sizeof(event)) ||
        sender.port != local.port || sender.groups != 0)
        return -1;
    info = CMSG_FIRSTHDR(&message);
    if (!info || memcmp(CMSG_DATA(info), relay_credentials, sizeof(relay_credentials)))
        return -1;

    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        destination.groups = 2;
        destination.port = 0;
        if (setgid(1000) || setuid(1000) || send(listener, event, sizeof(event), 0) != -1 ||
            errno != EPERM ||
            sendto(listener, event, sizeof(event), 0, (struct sockaddr*)&destination,
                   sizeof(destination)) != -1 ||
            errno != EPERM)
            _exit(1);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) ||
        recv(relay, data, sizeof(data), 0) != -1 || errno != EAGAIN)
        return -1;
    destination.groups = 1;
    destination.port = 0;
    if (sendto(listener, event, sizeof(event), 0, (struct sockaddr*)&destination,
               sizeof(destination)) != -1 ||
        errno != EOPNOTSUPP || close(route) || close(relay) || close(listener))
        return -1;
    puts("BOOT_INPUT_UEVENT_PASS");
    return 0;
}

static int check_usb_input(void) {
    enum { key_a = 30, key_b = 48, key_c = 46, button_left = 272 };

    struct input_event {
        int64_t seconds, microseconds;
        uint16_t type, code;
        int32_t value;
    } event;
    struct pollfd devices[] = {{open("/dev/input/event0", O_RDONLY), POLLIN, 0},
                               {open("/dev/input/event1", O_RDONLY), POLLIN, 0}};
    if (devices[0].fd < 0 || devices[1].fd < 0)
        return -1;
    uint8_t relative[2] = {0};
    if (ioctl(devices[1].fd, 0x80024522, relative) < 0 || (relative[0] & 3) != 3 ||
        !(relative[1] & 1))
        return -1;
    unsigned keys[3] = {0}, button = 0;
    int dx = 0, dy = 0;
    unsigned scroll = 0;
    puts("BOOT_USB_INPUT_READY");
    fflush(stdout);
    for (unsigned i = 0; i < 64; ++i) {
        if (poll(devices, 2, 8000) <= 0)
            return -1;
        for (unsigned j = 0; j < 2; ++j) {
            if (!(devices[j].revents & POLLIN))
                continue;
            if (read(devices[j].fd, &event, sizeof(event)) != sizeof(event))
                return -1;
            if (!j && event.type == 1 &&
                (event.code == key_a || event.code == key_b || event.code == key_c)) {
                unsigned* state = &keys[event.code == key_a ? 0 : event.code == key_b ? 1 : 2];
                if (*state > 1 || event.value != (int)(1 - *state))
                    return -1;
                ++*state;
            }
            if (j && event.type == 2 && event.code == 0)
                dx += event.value;
            if (j && event.type == 2 && event.code == 1)
                dy += event.value;
            if (j && event.type == 2 && event.code == 8) {
                if (scroll > 1 || event.value != (scroll ? -1 : 1))
                    return -1;
                puts(++scroll == 1 ? "BOOT_USB_MOUSE_SCROLL_UP" : "BOOT_USB_MOUSE_SCROLL_DOWN");
                fflush(stdout);
            }
            if (j && event.type == 1 && event.code == button_left) {
                if (button > 3 || event.value != (int)(1 - button % 2))
                    return -1;
                if (++button == 1) {
                    puts("BOOT_USB_MOUSE_PRESSED");
                    fflush(stdout);
                }
                if (button == 2) {
                    if (dx != 31 || dy != -19)
                        return -1;
                    puts("BOOT_USB_MOUSE_RELEASED");
                    fflush(stdout);
                }
                if (button == 3) {
                    puts("BOOT_USB_HOTPLUG_MOUSE_PRESSED");
                    fflush(stdout);
                }
            }
        }
        if (keys[0] == 2 && keys[1] == 2 && keys[2] == 2 && button == 4 && dx == 19 && dy == -12 &&
            scroll == 2) {
            puts("BOOT_USB_INPUT_PASS");
            return close(devices[0].fd) || close(devices[1].fd) ? -1 : 0;
        }
    }
    return -1;
}

static int check_framebuffer(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    volatile uint8_t* pixels = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pixels == MAP_FAILED)
        return -1;
    uint8_t original = pixels[0];
    uint8_t color = original ^ 0xff;
    pixels[0] = color;
    int ok = pixels[0] == color;
    pixels[0] = original;
    if (munmap((void*)pixels, page) || close(fd) || !ok)
        return -1;
    puts("BOOT_MEDIA_FRAMEBUFFER_PASS");
    return 0;
}

int main(int argc, char** argv) {
    char token[33] = {0};
    int fd = open("/boot-proof", O_RDONLY);
    if (argc != 1 || getpid() != 1 || fd < 0 ||
        read(fd, token, sizeof(token)) != sizeof(token) - 1 || close(fd) || check_framebuffer() ||
        check_input_inventory() || check_input_uevent() ||
        (!access("/boot-usb-input", F_OK) && check_usb_input()))
        return 1;
    printf("BOOT_MEDIA_PASS %s %s\n", argv[0], token);
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}
