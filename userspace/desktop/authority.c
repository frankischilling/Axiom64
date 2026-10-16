// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "authority.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char protocol[] = "MIT-MAGIC-COOKIE-1";

static int failed(int error) {
    errno = error;
    return -1;
}

static int bytes(int fd, void* data, size_t size, int writing) {
    size_t done = 0;
    while (done < size) {
        ssize_t count = writing ? write(fd, (char*)data + done, size - done)
                                : read(fd, (char*)data + done, size - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EINVAL);
        done += (size_t)count;
    }
    return 0;
}

static int field(int fd, const void* value, size_t size) {
    if (size > UINT16_MAX)
        return failed(EINVAL);
    uint8_t length[] = {(uint8_t)(size >> 8), (uint8_t)size};
    return bytes(fd, length, sizeof(length), 1) < 0 ? -1 : bytes(fd, (void*)value, size, 1);
}

int desktop_authority_write(int descriptor, unsigned display, const uint8_t cookie[16]) {
    if (!cookie || display > 65535)
        return failed(EINVAL);
    char hostname[256] = {0}, number[6];
    if (gethostname(hostname, sizeof(hostname)) < 0)
        return -1;
    size_t length = strnlen(hostname, sizeof(hostname));
    if (!length || length == sizeof(hostname))
        return failed(EINVAL);
    int size = snprintf(number, sizeof(number), "%u", display);
    uint8_t family[] = {1, 0}; // Xauthority FamilyLocal, big-endian 256.
    if (bytes(descriptor, family, sizeof(family), 1) < 0 ||
        field(descriptor, hostname, length) < 0 || field(descriptor, number, (size_t)size) < 0 ||
        field(descriptor, protocol, sizeof(protocol) - 1) < 0 || field(descriptor, cookie, 16) < 0)
        return -1;
    return 0;
}

static int next(const uint8_t* data, size_t size, size_t* at, const uint8_t** value,
                size_t* length) {
    if (*at > size || size - *at < 2)
        return failed(EINVAL);
    *length = (size_t)data[*at] * 256 + data[*at + 1];
    *at += 2;
    if (*length > size - *at)
        return failed(EINVAL);
    *value = data + *at;
    *at += *length;
    return 0;
}

int desktop_authority_read(const char* path, unsigned display, uint8_t cookie[16]) {
    if (cookie)
        explicit_bzero(cookie, 16);
    if (!path || !cookie || display > 65535)
        return failed(EINVAL);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat metadata;
    int error = fstat(fd, &metadata) < 0 ? errno : 0;
    if (!error && (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1 || metadata.st_size < 2 ||
                   metadata.st_size > 512))
        error = EINVAL;
    uint8_t data[512] = {0};
    if (!error && bytes(fd, data, (size_t)metadata.st_size, 0) < 0)
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    size_t at = 2, length;
    const uint8_t* value;
    char hostname[256] = {0}, number[6];
    int number_size = snprintf(number, sizeof(number), "%u", display);
    if (!error && gethostname(hostname, sizeof(hostname)) < 0)
        error = errno;
    if (!error &&
        (data[0] != 1 || data[1] != 0 ||
         next(data, (size_t)metadata.st_size, &at, &value, &length) < 0 ||
         length != strnlen(hostname, sizeof(hostname)) || memcmp(value, hostname, length)))
        error = EINVAL;
    if (!error && (next(data, (size_t)metadata.st_size, &at, &value, &length) < 0 ||
                   length != (size_t)number_size || memcmp(value, number, length)))
        error = EINVAL;
    if (!error && (next(data, (size_t)metadata.st_size, &at, &value, &length) < 0 ||
                   length != sizeof(protocol) - 1 || memcmp(value, protocol, length)))
        error = EINVAL;
    if (!error && (next(data, (size_t)metadata.st_size, &at, &value, &length) < 0 || length != 16 ||
                   at != (size_t)metadata.st_size))
        error = EINVAL;
    if (!error)
        memcpy(cookie, value, 16);
    else
        explicit_bzero(cookie, 16);
    explicit_bzero(data, sizeof(data));
    return error ? failed(error) : 0;
}
