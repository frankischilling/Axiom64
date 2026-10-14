// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "EXT2_DELETED_RECOVERY_FAIL line=%d errno=%d expression=%s\n",         \
                    __LINE__, errno, #value);                                                      \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

int main(int argc, char** argv) {
    CHECK((argc == 3 || argc == 4) && !getuid() && !geteuid());
    struct stat device;
    CHECK(stat("/dev/vda", &device) == 0 && S_ISBLK(device.st_mode));
    CHECK(mkdir("/mnt", 0755) == 0 || errno == EEXIST);
    CHECK(mkdir("/mnt/recovery", 0755) == 0);
    unsigned long flags = !strcmp(argv[1], "checked-ro") ? MS_RDONLY : 0;
    const char* options = !strcmp(argv[1], "default") ? NULL : "recovery=check";
    int expected = atoi(argv[2]);
    int result = mount("/dev/vda", "/mnt/recovery", "ext2", flags, options);
    if (expected) {
        CHECK(result == -1 && errno == expected);
        printf("EXT2_DELETED_RECOVERY_DENIED mode=%s errno=%d\n", argv[1], errno);
    } else {
        CHECK(result == 0);
        if (argc == 4) {
            struct stat value;
            char target[64] = {0};
            CHECK(lstat("/mnt/recovery/build-static/db/current", &value) == 0 &&
                  S_ISLNK(value.st_mode) && !value.st_uid && !value.st_gid && value.st_nlink == 1);
            CHECK(readlink("/mnt/recovery/build-static/db/current", target, sizeof(target)) == 34 &&
                  !memcmp(target, "g-", 2));
            int fd = open("/mnt/recovery/build-static/db/current/passwd", O_RDONLY | O_CLOEXEC);
            CHECK(fd >= 0);
            char header[5];
            CHECK(read(fd, header, sizeof(header)) == sizeof(header) &&
                  !memcmp(header, "root:", sizeof(header)) && close(fd) == 0);
            if (!strcmp(argv[3], "directory")) {
                const char* path =
                    "/mnt/recovery/build-static/db/g-ddf7c441df09912037b60d0ac8f2d736";
                CHECK(lstat(path, &value) == 0 && S_ISDIR(value.st_mode) && !value.st_uid &&
                      !value.st_gid && value.st_nlink == 2);
                DIR* directory = opendir(path);
                CHECK(directory != NULL);
                unsigned entries = 0;
                struct dirent* entry;
                errno = 0;
                while ((entry = readdir(directory))) {
                    CHECK(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."));
                    entries++;
                }
                CHECK(!errno && entries == 2 && closedir(directory) == 0);
            }
        } else {
            int fd = open("/mnt/recovery/rotation/records/journal", O_RDONLY | O_CLOEXEC);
            CHECK(fd >= 0);
            unsigned char header[4];
            CHECK(read(fd, header, sizeof(header)) == sizeof(header) &&
                  memcmp(header, "A46L", sizeof(header)) == 0 && close(fd) == 0);
        }
        CHECK(umount("/mnt/recovery") == 0);
        printf("EXT2_DELETED_RECOVERY_PASS mode=%s mounted=1 clean_unmount=1\n", argv[1]);
    }
    return 0;
}
