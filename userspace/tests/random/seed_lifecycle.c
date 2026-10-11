// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RANDOM_LINKAGE
#define RANDOM_LINKAGE "native"
#endif

static const char* directory;

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "RANDOM_SEED_PROBE_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

static int entropy_count(void) {
    int fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
    require(fd >= 0, "random-open");
    int count = -1;
    require(ioctl(fd, 0x80045200U, &count) == 0, "entropy-count");
    require(close(fd) == 0, "random-close");
    return count;
}

static void service(const char* operation, int nonblock, int expected) {
    pid_t child = fork();
    require(child >= 0, "service-fork");
    if (!child) {
        if (nonblock)
            execl("/sbin/random-seed", "random-seed", operation, "--directory", directory,
                  "--nonblock", (char*)0);
        else
            execl("/sbin/random-seed", "random-seed", operation, "--directory", directory,
                  (char*)0);
        perror("random-seed probe: service exec");
        _exit(127);
    }
    int status = -1;
    pid_t result;
    do {
        result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    require(result == child && WIFEXITED(status) && WEXITSTATUS(status) == expected,
            "service-result");
    printf("RANDOM_SEED_PROBE_SERVICE mode=%s nonblock=%d status=%d pid=%d\n", operation, nonblock,
           WEXITSTATUS(status), child);
}

static int seed(unsigned char output[32], struct stat* status) {
    int directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0 && errno == ENOENT)
        return 0;
    require(directory_fd >= 0, "seed-directory-open");
    int fd = openat(directory_fd, "seed", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    require(close(directory_fd) == 0, "seed-directory-close");
    if (fd < 0 && errno == ENOENT)
        return 0;
    require(fd >= 0, "seed-open");
    require(fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
                (status->st_mode & 07777) == 0600 && status->st_uid == 0 && status->st_gid == 0 &&
                status->st_nlink == 1 && status->st_size == 32,
            "seed-metadata");
    size_t at = 0;
    while (at < 32) {
        ssize_t count = read(fd, output + at, 32 - at);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "seed-read");
        at += count;
    }
    require(close(fd) == 0, "seed-close");
    return 1;
}

int main(int argc, char** argv) {
    require(argc == 3 && (!strcmp(argv[1], "rotate") || !strcmp(argv[1], "unready") ||
                          !strcmp(argv[1], "readonly")),
            "arguments");
    setbuf(stdout, NULL);
    require(geteuid() == 0 && getegid() == 0, "root-identity");
    const char* mode = argv[1];
    const char* mountpoint = argv[2];
    require(mountpoint[0] == '/' && strlen(mountpoint) < 900, "mountpoint");
    int readonly = !strcmp(mode, "readonly");
    require(mount("/dev/vda", mountpoint, "ext2", readonly ? MS_RDONLY : 0, NULL) == 0,
            "ext2-mount");
    char path[1024];
    require(snprintf(path, sizeof(path), "%s/random", mountpoint) > 0, "private-path");
    directory = path;
    unsigned char original[32], current[32];
    struct stat before, after;
    int present = seed(original, &before);
    int bits = entropy_count();
    require(bits == (!strcmp(mode, "unready") ? 0 : 256), "initial-readiness");
    if (!strcmp(mode, "unready") || readonly)
        require(present, "existing-seed-required");
    service("load", 0, 0);
    require(entropy_count() == bits, "uncredited-load");
    if (present) {
        require(seed(current, &after) && !memcmp(original, current, 32) &&
                    before.st_ino == after.st_ino,
                "load-preserves-seed");
    }
    if (!strcmp(mode, "unready")) {
        unsigned char byte;
        errno = 0;
        require(getrandom(&byte, 1, GRND_NONBLOCK) == -1 && errno == EAGAIN, "unready-output");
        service("boot", 1, 1);
        require(entropy_count() == 0, "persisted-seed-never-credits");
        require(seed(current, &after) && !memcmp(original, current, 32) &&
                    before.st_ino == after.st_ino,
                "failed-rotation-preserves-seed");
    } else if (readonly) {
        service("boot", 1, 1);
        require(seed(current, &after) && !memcmp(original, current, 32) &&
                    before.st_ino == after.st_ino,
                "readonly-preserves-seed");
    } else {
        service("boot", 0, 0);
        require(seed(current, &after), "rotated-seed-present");
        require(!present || memcmp(original, current, 32), "rotation-replaces-payload");
        int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        require(fd >= 0, "rotation-directory");
        struct stat status;
        errno = 0;
        require(fstatat(fd, "seed.previous", &status, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT,
                "checkpoint-cleanup");
        int lock = openat(fd, "lock", O_RDONLY | O_CLOEXEC);
        require(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0, "probe-singleton-ownership");
        service("load", 0, 1);
        require(close(lock) == 0, "probe-singleton-close");
        service("load", 0, 0);
        require(fsync(fd) == 0 && close(fd) == 0, "rotation-directory-sync");
    }
    printf("RANDOM_SEED_PROBE_METADATA mode=%o uid=%u gid=%u links=%lu size=%lld\n",
           after.st_mode & 07777, after.st_uid, after.st_gid, (unsigned long)after.st_nlink,
           (long long)after.st_size);
    printf(
        "RANDOM_SEED_PROBE_PASS linkage=%s mode=%s previous=%d credited_bits=0 entropy_bits=%d\n",
        RANDOM_LINKAGE, mode, present, entropy_count());
    require(umount(mountpoint) == 0, "ext2-unmount");
    return 0;
}
