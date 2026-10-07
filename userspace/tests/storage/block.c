// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define BLKROGET 0x125e
#define BLKGETSIZE 0x1260
#define BLKFLSBUF 0x1261
#define BLKSSZGET 0x1268
#define BLKGETSIZE64 0x80081272
#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "STORAGE_FAIL line=%d: %s errno=%d (%s)\n", __LINE__, #expr, errno,    \
                    strerror(errno));                                                              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum {
    CAPACITY = 8 * 1024 * 1024,
    START = 8192 + 37,
    LENGTH = 16384 + 713,
    ERROR_READ = 12328,
    ERROR_WRITE = 12348
};

static unsigned char payload[LENGTH], actual[LENGTH];

static void filled(const unsigned char* bytes, size_t length, unsigned char value) {
    for (size_t i = 0; i < length; i++)
        CHECK(bytes[i] == value);
}

static void metadata(int fd, uint64_t capacity, int readonly, unsigned minor_number) {
    struct stat stat;
    CHECK(fstat(fd, &stat) == 0 && S_ISBLK(stat.st_mode));
    CHECK(major(stat.st_rdev) == 252 && minor(stat.st_rdev) == minor_number);
    CHECK(stat.st_size == 0);
    uint64_t bytes = 0;
    unsigned long sectors = 0;
    int size = 0, ro = -1;
    CHECK(ioctl(fd, BLKGETSIZE64, &bytes) == 0 && bytes == capacity);
    CHECK(ioctl(fd, BLKGETSIZE, &sectors) == 0 && sectors == capacity / 512);
    CHECK(ioctl(fd, BLKSSZGET, &size) == 0 && size == 512);
    CHECK(ioctl(fd, BLKROGET, &ro) == 0 && ro == readonly);
    CHECK(lseek(fd, 0, SEEK_END) == (off_t)capacity);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    errno = 0;
    CHECK(ioctl(fd, BLKGETSIZE64, (void*)1) == -1 && errno == EFAULT);
    errno = 0;
    CHECK(ioctl(fd, 0x1234, &bytes) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(pread(fd, actual, 1, -1) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(syscall(SYS_read, fd, (void*)1, 512) == -1 && errno == EFAULT);
    CHECK(read(fd, actual, 0) == 0);
    CHECK(pread(fd, actual, 1, capacity) == 0);
    CHECK(pread(fd, actual, 1, capacity + 512) == 0);
    CHECK(lseek(fd, 0, SEEK_CUR) == 0);
}

static void persisted(int fd) {
    CHECK(lseek(fd, 123, SEEK_SET) == 123);
    CHECK(pread(fd, actual, LENGTH, START) == LENGTH);
    CHECK(!memcmp(actual, payload, LENGTH));
    CHECK(lseek(fd, 0, SEEK_CUR) == 123);
    CHECK(pread(fd, actual, 32, START - 32) == 32);
    filled(actual, 32, 0xa5);
    CHECK(pread(fd, actual, 32, START + LENGTH) == 32);
    filled(actual, 32, 0xa5);
    CHECK(pread(fd, actual, 257, CAPACITY - 257) == 257);
    CHECK(!memcmp(actual, payload, 257));
    CHECK(pread(fd, actual, 32, CAPACITY - 257 - 32) == 32);
    filled(actual, 32, 0xa5);
}

int main(int argc, char** argv) {
    CHECK(argc == 2);
    const char* phase = argv[1];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (i * 31 + 17) & 255;
    int fd = open("/dev/vda", O_RDONLY);
    CHECK(fd >= 0);
    errno = 0;
    CHECK(open("/dev/vda", O_RDONLY | O_DIRECT) == -1 && errno == EINVAL);
    metadata(fd, CAPACITY, !strcmp(phase, "readonly"), 0);
    CHECK(pread(fd, actual, 18, 0) == 18 && !memcmp(actual, "AXIOM64-DISK-FIRST\n", 18));
    errno = 0;
    CHECK(write(fd, payload, 1) == -1 && errno == EBADF);
    int second = open("/dev/vdb", O_RDONLY);
    CHECK(second >= 0);
    metadata(second, CAPACITY / 2, 1, 16);
    CHECK(pread(second, actual, 19, 0) == 19 && !memcmp(actual, "AXIOM64-DISK-SECOND\n", 19));
    CHECK(pread(second, actual, 512, CAPACITY / 2 - 512) == 512);
    filled(actual, 512, 0x3c);
    errno = 0;
    CHECK(open("/dev/vdb", O_RDWR) == -1 && errno == EROFS);
    CHECK(close(second) == 0);
    if (!strcmp(phase, "readonly")) {
        persisted(fd);
        errno = 0;
        CHECK(open("/dev/vda", O_RDWR) == -1 && errno == EROFS);
        CHECK(fsync(fd) == 0);
        puts("STORAGE_READONLY_PASS");
    } else if (!strcmp(phase, "verify")) {
        persisted(fd);
        puts("STORAGE_REBOOT_PASS");
    } else {
        CHECK(close(fd) == 0);
        fd = open("/dev/vda", O_RDWR);
        CHECK(fd >= 0);
        errno = 0;
        CHECK(ftruncate(fd, 0) == -1 && errno == EINVAL);
        errno = 0;
        CHECK(truncate("/dev/vda", 0) == -1 && errno == EINVAL);
        errno = 0;
        CHECK(pwrite(fd, payload, 1, -1) == -1 && errno == EINVAL);
        CHECK(write(fd, payload, 0) == 0);
        if (!strcmp(phase, "write") || !strcmp(phase, "queue")) {
            CHECK(lseek(fd, START, SEEK_SET) == START);
            CHECK(write(fd, payload, LENGTH) == LENGTH);
            CHECK(lseek(fd, 0, SEEK_CUR) == START + LENGTH);
            CHECK(pwrite(fd, payload, 514, CAPACITY - 257) == 257);
            CHECK(lseek(fd, 0, SEEK_CUR) == START + LENGTH);
            errno = 0;
            CHECK(pwrite(fd, payload, 1, CAPACITY) == -1 && errno == ENOSPC);
            CHECK(fsync(fd) == 0);
            CHECK(fdatasync(fd) == 0);
            CHECK(ioctl(fd, BLKFLSBUF, 0) == 0);
            persisted(fd);
            // Default matrix crosses the 16-bit index; geometry cases cross ring slots.
            unsigned requests = !strcmp(phase, "queue") ? 2052 : 65540;
            for (unsigned i = 0; i < requests; i++) {
                CHECK(pread(fd, actual, 512, 0) == 512);
                CHECK(!memcmp(actual, "AXIOM64-DISK-FIRST\n", 18));
            }
            if (!strcmp(phase, "queue"))
                puts("STORAGE_QUEUE_WRAP_PASS requests=2052");
            else
                puts("STORAGE_RING_WRAP_PASS requests=65540");
            puts("STORAGE_WRITE_PASS");
        } else if (!strcmp(phase, "error")) {
            // The host injects one backend error for each of these operations.
            CHECK(lseek(fd, ERROR_READ * 512, SEEK_SET) == ERROR_READ * 512);
            errno = 0;
            CHECK(read(fd, actual, 512) == -1 && errno == EIO);
            CHECK(lseek(fd, 0, SEEK_CUR) == ERROR_READ * 512);
            CHECK(read(fd, actual, 512) == 512);
            filled(actual, 512, 0xa5);
            CHECK(lseek(fd, ERROR_WRITE * 512, SEEK_SET) == ERROR_WRITE * 512);
            memset(actual, 0x6e, 512);
            errno = 0;
            CHECK(write(fd, actual, 512) == -1 && errno == EIO);
            CHECK(lseek(fd, 0, SEEK_CUR) == ERROR_WRITE * 512);
            CHECK(write(fd, actual, 512) == 512);
            errno = 0;
            CHECK(fsync(fd) == -1 && errno == EIO);
            CHECK(fsync(fd) == 0);
            CHECK(pread(fd, actual, 512, ERROR_WRITE * 512) == 512);
            filled(actual, 512, 0x6e);
            int synced = open("/dev/vda", O_WRONLY | O_DSYNC);
            CHECK(synced >= 0);
            CHECK(pwrite(synced, actual, 1, ERROR_WRITE * 512 + 7) == 1);
            CHECK(close(synced) == 0);
            synced = open("/dev/vda", O_WRONLY | O_SYNC);
            CHECK(synced >= 0);
            CHECK(pwrite(synced, actual, 1, ERROR_WRITE * 512 + 9) == 1);
            CHECK(close(synced) == 0);
            puts("STORAGE_BACKEND_ERROR_PASS");
        } else
            CHECK(0);
    }
    CHECK(close(fd) == 0);
    printf("STORAGE_PHASE_PASS phase=%s\n", phase);
    return 0;
}
