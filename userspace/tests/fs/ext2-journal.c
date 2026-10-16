// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "EXT2_JOURNAL_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno, \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void all(int fd, const unsigned char* data, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(fd, data + done, length - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
}

int main(int argc, char** argv) {
    CHECK(argc == 2 && !getuid() && !geteuid());
    CHECK(mkdir("/mnt", 0755) == 0 || errno == EEXIST);
    CHECK(mkdir("/mnt/journal", 0755) == 0);
    CHECK(mount("/dev/vda", "/mnt/journal", "ext2", 0, NULL) == 0);
    struct statfs filesystem;
    CHECK(statfs("/mnt/journal", &filesystem) == 0 && filesystem.f_type == 0xef53 &&
          (filesystem.f_bsize == 1024 || filesystem.f_bsize == 2048 || filesystem.f_bsize == 4096));
    size_t size = (size_t)filesystem.f_bsize;
    size_t historical = 9 * size - 128, length = historical + 448;
    int fd = open("/mnt/journal/seed", O_RDWR | O_CLOEXEC);
    struct stat value;
    CHECK(fd >= 0 && fstat(fd, &value) == 0 && value.st_size == (off_t)length &&
          S_ISREG(value.st_mode) && value.st_uid == 0 && value.st_gid == 0 && value.st_nlink == 1);
    unsigned char* data = malloc(length + 2 * size + 37);
    CHECK(data != NULL);
    size_t done = 0;
    while (done < length) {
        ssize_t count = read(fd, data + done, length - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
    for (size_t index = 0; index < historical; index++)
        CHECK(data[index] == (unsigned char)(index * 31 + 17));
    for (size_t index = 0; index < 448; index++)
        CHECK(data[historical + index] == (unsigned char)(index * 13 + 9));
    if (!strcmp(argv[1], "write")) {
        size_t extra = 2 * size + 37;
        for (size_t index = 0; index < extra; index++)
            data[length + index] = (unsigned char)(index * 7 + 3);
        all(fd, data + length, extra);
        CHECK(fsync(fd) == 0);
        CHECK(mkdir("/mnt/journal/work", 0700) == 0);
        int created = open("/mnt/journal/work/new", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        CHECK(created >= 0);
        all(created, data, size + 97);
        CHECK(fsync(created) == 0 && close(created) == 0);
        CHECK(rename("/mnt/journal/work/new", "/mnt/journal/work/final") == 0);
        int parent = open("/mnt/journal/work", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(parent >= 0 && fsync(parent) == 0 && close(parent) == 0);
    } else
        CHECK(!strcmp(argv[1], "read"));
    CHECK(close(fd) == 0);
    free(data);
    CHECK(umount("/mnt/journal") == 0);
    printf("EXT2_JOURNAL_PASS mode=%s block_size=%zu historical_bytes=%zu\n", argv[1], size,
           historical);
    return 0;
}
