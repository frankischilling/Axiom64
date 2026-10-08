// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "DISK_ROOT_FAIL line=%d: %s errno=%d\n", __LINE__, #condition, errno); \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static unsigned char payload[8193], actual[8193];

static int store(const char* name) {
    int fd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, payload, sizeof(payload)) == (ssize_t)sizeof(payload));
    CHECK(fchmod(fd, 0640) == 0);
    struct timespec dates[] = {{123456789, 0}, {234567890, 0}};
    CHECK(futimens(fd, dates) == 0);
    CHECK(fsync(fd) == 0);
    CHECK(close(fd) == 0);
    return 0;
}

static int verify(const char* name) {
    struct stat metadata;
    CHECK(stat(name, &metadata) == 0);
    CHECK(metadata.st_size == (off_t)sizeof(payload) && (metadata.st_mode & 0777) == 0640);
    CHECK(metadata.st_mtim.tv_sec == 234567890 && metadata.st_mtim.tv_nsec == 0);
    int fd = open(name, O_RDONLY);
    CHECK(fd >= 0 && read(fd, actual, sizeof(actual)) == (ssize_t)sizeof(actual));
    CHECK(!memcmp(actual, payload, sizeof(actual)));
    CHECK(read(fd, actual, 1) == 0 && close(fd) == 0);
    return 0;
}

static int coherence(const char* name) {
    int writer = open(name, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int reader = open(name, O_RDONLY);
    CHECK(writer >= 0 && reader >= 0);
    CHECK(write(writer, "before", 6) == 6);
    CHECK(pread(reader, actual, 6, 0) == 6 && !memcmp(actual, "before", 6));
    CHECK(pwrite(writer, "after!", 6, 0) == 6);
    CHECK(pread(reader, actual, 6, 0) == 6 && !memcmp(actual, "after!", 6));
    CHECK(ftruncate(writer, 2) == 0);
    struct stat metadata;
    CHECK(fstat(reader, &metadata) == 0 && metadata.st_size == 2);
    CHECK(pread(reader, actual, 6, 0) == 2 && !memcmp(actual, "af", 2));
    CHECK(unlink(name) == 0);
    CHECK(pread(reader, actual, 6, 0) == 2 && !memcmp(actual, "af", 2));
    CHECK(close(writer) == 0 && close(reader) == 0);
    return 0;
}

static int open_orphan(const char* name) {
    int fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "shutdown orphan", 15) == 15);
    CHECK(unlink(name) == 0);
    struct stat metadata;
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_nlink == 0);
    CHECK(pread(fd, actual, 15, 0) == 15 && !memcmp(actual, "shutdown orphan", 15));
    // Keep the description open until the guest powers off.
    return 0;
}

int main(void) {
    const char* phase = getenv("AXIOM64_PHASE");
    CHECK(phase &&
          (!strcmp(phase, "write") || !strcmp(phase, "verify") || !strcmp(phase, "readonly")));
    int readonly = !strcmp(phase, "readonly");
    for (unsigned i = 0; i < sizeof(payload); i++)
        payload[i] = (i * 31 + 17) & 255;
    struct statfs filesystem;
    struct stat root, temporary, alias;
    CHECK(statfs("/", &filesystem) == 0 && filesystem.f_type == 0xef53);
    CHECK(!!(filesystem.f_flags & ST_RDONLY) == readonly);
    CHECK(stat("/", &root) == 0 && stat("/tmp", &temporary) == 0 &&
          root.st_dev != temporary.st_dev);
    CHECK(mount("/dev/vdb", "/mnt/data", "ext2", readonly ? MS_RDONLY : 0, NULL) == 0);
    if (!strcmp(phase, "write")) {
        CHECK(mkdir("/root/root-persistence", 0750) == 0);
        CHECK(coherence("/root/root-persistence/coherence") == 0);
        CHECK(coherence("/mnt/data/coherence") == 0);
        puts("DISK_ROOT_COHERENCE_PASS");
        CHECK(store("/root/root-persistence/original") == 0);
        CHECK(link("/root/root-persistence/original", "/root/root-persistence/payload") == 0);
        CHECK(unlink("/root/root-persistence/original") == 0);
        CHECK(symlink("payload", "/root/root-persistence/alias") == 0);
        CHECK(store("/mnt/data/original") == 0);
        CHECK(rename("/mnt/data/original", "/mnt/data/payload") == 0);
    }
    CHECK(verify("/root/root-persistence/payload") == 0);
    CHECK(verify("/root/root-persistence/alias") == 0);
    CHECK(verify("/mnt/data/payload") == 0);
    CHECK(chdir("/root/root-persistence") == 0);
    char cwd[128];
    CHECK(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, "/root/root-persistence"));
    CHECK(stat("payload", &temporary) == 0 && stat("alias", &alias) == 0 &&
          alias.st_ino == temporary.st_ino);
    CHECK(stat("../..", &alias) == 0 && alias.st_ino == root.st_ino && alias.st_dev == root.st_dev);
    if (readonly) {
        errno = 0;
        CHECK(open("payload", O_WRONLY) == -1 && errno == EROFS);
        errno = 0;
        CHECK(unlink("payload") == -1 && errno == EROFS);
        errno = 0;
        CHECK(chmod("payload", 0600) == -1 && errno == EROFS);
        errno = 0;
        CHECK(open("/mnt/data/payload", O_WRONLY) == -1 && errno == EROFS);
    }
    CHECK(chdir("/") == 0);
    if (!strcmp(phase, "write")) {
        CHECK(open_orphan("/root/root-persistence/open-orphan") == 0);
        CHECK(open_orphan("/mnt/data/open-orphan") == 0);
    } else {
        CHECK(umount("/mnt/data") == 0);
    }
    sync();
    puts(!strcmp(phase, "write") ? "DISK_ROOT_WRITE_PASS"
         : readonly              ? "DISK_ROOT_READONLY_PASS"
                                 : "DISK_ROOT_REBOOT_PASS");
    printf("DISK_ROOT_PHASE_PASS phase=%s\n", phase);
    if (!strcmp(phase, "write")) {
        puts("DISK_ROOT_OPEN_UNLINK_SHUTDOWN_READY");
        CHECK(fflush(stdout) == 0);
        CHECK(reboot(RB_POWER_OFF) == 0);
    }
    return 0;
}
