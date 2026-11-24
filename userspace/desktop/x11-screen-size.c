// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/desktop/x11-screen-size.c
 * @brief   Read the size of the authenticated local X11 screen.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Reads the initial screen dimensions from the X11 connection setup reply.
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
#include "authority.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static const char cookie_protocol[] = "MIT-MAGIC-COOKIE-1";

static int transfer(int fd, void* buffer, size_t size, int sending) {
    uint8_t* bytes = buffer;
    while (size) {
        ssize_t count = sending ? send(fd, bytes, size, MSG_NOSIGNAL) : read(fd, bytes, size);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        bytes += count;
        size -= (size_t)count;
    }
    return 0;
}

static unsigned read16(const uint8_t* bytes) {
    return (unsigned)bytes[0] | (unsigned)bytes[1] << 8;
}

static int screen_size(int fd, const uint8_t cookie[16]) {
    enum {
        request_header = 12,
        protocol_padded_size = (sizeof(cookie_protocol) + 2) & ~3u,
        setup_header = 32,
        format_size = 8,
        screen_header = 40
    };

    uint8_t request[request_header + protocol_padded_size + 16] = {
        [0] = 'l', [2] = 11, [6] = sizeof(cookie_protocol) - 1, [8] = 16};
    memcpy(request + request_header, cookie_protocol, sizeof(cookie_protocol) - 1);
    memcpy(request + request_header + protocol_padded_size, cookie, 16);
    uint8_t reply[8];
    if (transfer(fd, request, sizeof(request), 1) < 0 ||
        transfer(fd, reply, sizeof(reply), 0) < 0 || reply[0] != 1)
        return -1;

    size_t length = (size_t)read16(reply + 6) * 4;
    if (length < setup_header + screen_header)
        return -1;
    uint8_t* setup = malloc(length);
    if (!setup)
        return -1;
    int result = -1;
    if (transfer(fd, setup, length, 0) == 0 && setup[20]) {
        size_t vendor_size = (read16(setup + 16) + 3) & ~3u;
        size_t screen = setup_header + vendor_size + (size_t)setup[21] * format_size;
        if (screen <= length - screen_header) {
            unsigned width = read16(setup + screen + 20);
            unsigned height = read16(setup + screen + 22);
            if (width && height)
                result = printf("%u %u\n", width, height) < 0 ? -1 : 0;
        }
    }
    free(setup);
    return result;
}

int main(void) {
    const char* display = getenv("DISPLAY");
    const char* authority = getenv("XAUTHORITY");
    if (!display || !authority)
        return 1;
    if (!strncmp(display, "unix:", 5))
        display += 4;
    if (*display != ':' || display[1] < '0' || display[1] > '9')
        return 1;
    char* end;
    unsigned long number = strtoul(display + 1, &end, 10);
    if (number > 65535 || (*end && strcmp(end, ".0")))
        return 1;
    uint8_t cookie[16];
    if (desktop_authority_read_local(authority, (unsigned)number, cookie) < 0)
        return 1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int length =
        snprintf(address.sun_path, sizeof(address.sun_path), "/tmp/.X11-unix/X%lu", number);
    if (length < 0 || (size_t)length >= sizeof(address.sun_path))
        return 1;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 1;
    const struct timeval timeout = {.tv_sec = 1};
    int result = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
        connect(fd, (const struct sockaddr*)&address, sizeof(address)) == 0)
        result = screen_size(fd, cookie) < 0;
    close(fd);
    return result;
}
