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
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "JOURNAL_LIFETIME_FAIL line=%d errno=%d\n", __LINE__, errno);          \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void counts(const char* phase) {
    struct statfs value;
    CHECK(statfs("/mnt/data", &value) == 0 && value.f_type == 0xef53);
    printf("JOURNAL_LIFETIME_COUNTS phase=%s blocks=%llu inodes=%llu block_size=%lu\n", phase,
           (unsigned long long)value.f_bfree, (unsigned long long)value.f_ffree,
           (unsigned long)value.f_bsize);
}

static void all(int fd, const void* data, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(fd, (const char*)data + done, length - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
}

int main(int argc, char** argv) {
    CHECK(argc == 2 && !getuid() && !geteuid());
    CHECK(mkdir("/mnt", 0755) == 0 || errno == EEXIST);
    CHECK(mkdir("/mnt/data", 0755) == 0);
    int readonly = !strcmp(argv[1], "readonly") || !strcmp(argv[1], "reject-hardware") ||
                   !strcmp(argv[1], "reject-readonly");
    int expected = !strcmp(argv[1], "reject-unsupported") ? EOPNOTSUPP
                   : !strcmp(argv[1], "reject-hardware")  ? EROFS
                                                          : EUCLEAN;
    errno = 0;
    int mounted = mount("/dev/vda", "/mnt/data", "ext2", readonly ? MS_RDONLY : 0, NULL);
    if (!strncmp(argv[1], "reject-", 7)) {
        CHECK(mounted == -1 && errno == expected);
        puts("JOURNAL_LIFETIME_REJECT_PASS");
        return 0;
    }
    CHECK(mounted == 0);
    struct statfs filesystem;
    CHECK(statfs("/mnt/data", &filesystem) == 0 && filesystem.f_type == 0xef53);
    size_t size = (size_t)filesystem.f_bsize;
    CHECK(size == 1024 || size == 2048 || size == 4096);
    if (!strcmp(argv[1], "hold")) {
        struct timespec before, after;
        CHECK(clock_gettime(CLOCK_REALTIME, &before) == 0);
        counts("baseline");
        int fd = open("/mnt/data/retired", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        CHECK(fd >= 0);
        size_t length = 13 * size + 37;
        unsigned char* data = malloc(length);
        CHECK(data);
        for (size_t index = 0; index < length; index++)
            data[index] = (unsigned char)(index * 19 + 11);
        all(fd, data, length);
        CHECK(fsetxattr(fd, "user.lifetime", "retired", 7, 0) == 0);
        CHECK(fsync(fd) == 0 && unlink("/mnt/data/retired") == 0);
        const char tail[] = "after-unlink";
        CHECK(pwrite(fd, tail, sizeof(tail), (off_t)length) == sizeof(tail) && fsync(fd) == 0);
        unsigned char readback[37];
        CHECK(pread(fd, readback, sizeof(readback), 0) == sizeof(readback));
        CHECK(!memcmp(readback, data, sizeof(readback)));
        free(data);
        CHECK(symlink("seed", "/mnt/data/retired-link") == 0);
        int link = open("/mnt/data/retired-link", O_PATH | O_NOFOLLOW | O_CLOEXEC);
        CHECK(link >= 0 && unlink("/mnt/data/retired-link") == 0);
        char target[8];
        CHECK(readlinkat(link, "", target, sizeof(target)) == 4 && !memcmp(target, "seed", 4));
        CHECK(mkdir("/mnt/data/retired-directory", 0700) == 0);
        int directory = open("/mnt/data/retired-directory", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(directory >= 0 && rmdir("/mnt/data/retired-directory") == 0);
        struct stat file, symlink, folder;
        CHECK(fstat(fd, &file) == 0 && !file.st_nlink && S_ISREG(file.st_mode));
        CHECK(fstat(link, &symlink) == 0 && !symlink.st_nlink && S_ISLNK(symlink.st_mode));
        CHECK(fstat(directory, &folder) == 0 && !folder.st_nlink && S_ISDIR(folder.st_mode));
        CHECK(clock_gettime(CLOCK_REALTIME, &after) == 0);
        CHECK(file.st_ctim.tv_sec >= before.tv_sec && file.st_ctim.tv_sec <= after.tv_sec);
        CHECK(symlink.st_ctim.tv_sec >= before.tv_sec && symlink.st_ctim.tv_sec <= after.tv_sec);
        CHECK(folder.st_ctim.tv_sec >= before.tv_sec && folder.st_ctim.tv_sec <= after.tv_sec);
        printf(
            "JOURNAL_LIFETIME_CLOCK before=%lld after=%lld file=%lld symlink=%lld directory=%lld\n",
            (long long)before.tv_sec, (long long)after.tv_sec, (long long)file.st_ctim.tv_sec,
            (long long)symlink.st_ctim.tv_sec, (long long)folder.st_ctim.tv_sec);
        printf("JOURNAL_LIFETIME_ARMED file=%llu symlink=%llu directory=%llu\n",
               (unsigned long long)file.st_ino, (unsigned long long)symlink.st_ino,
               (unsigned long long)folder.st_ino);
        CHECK(fflush(stdout) == 0);
        for (;;)
            pause();
    }
    CHECK(!strcmp(argv[1], "verify") || readonly);
    struct stat value;
    const char* names[] = {"/mnt/data/retired", "/mnt/data/retired-link",
                           "/mnt/data/retired-directory"};
    for (unsigned index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        errno = 0;
        CHECK(lstat(names[index], &value) == -1 && errno == ENOENT);
    }
    size_t length = 9 * size - 128;
    unsigned char* data = malloc(length);
    CHECK(data);
    int fd = open("/mnt/data/seed", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && fstat(fd, &value) == 0 && value.st_size == (off_t)length);
    size_t done = 0;
    while (done < length) {
        ssize_t count = read(fd, data + done, length - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
    for (size_t index = 0; index < length; index++)
        CHECK(data[index] == (unsigned char)(index * 31 + 17));
    CHECK(close(fd) == 0);
    free(data);
    counts("recovered");
    errno = 0;
    fd = open("/mnt/data/fresh", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (readonly)
        CHECK(fd == -1 && errno == EROFS);
    else {
        const char payload[] = "new allocation after recovery";
        CHECK(fd >= 0);
        all(fd, payload, sizeof(payload));
        CHECK(fsync(fd) == 0 && close(fd) == 0 && unlink("/mnt/data/fresh") == 0);
        counts("after-allocation");
    }
    CHECK(umount("/mnt/data") == 0);
    printf("JOURNAL_LIFETIME_PASS mode=%s\n", argv[1]);
    return 0;
}
