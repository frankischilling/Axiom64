// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RANDOM_LINKAGE
#define RANDOM_LINKAGE "static"
#endif

static const char* directory = "/mnt/seed/random";

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "RANDOM_SEED_FAULT_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

static int service(const char* operation) {
    pid_t child = fork();
    require(child >= 0, "service-fork");
    if (!child) {
        execl("/sbin/random-seed", "random-seed", operation, "--directory", directory, "--nonblock",
              (char*)0);
        _exit(127);
    }
    int status;
    pid_t result;
    do {
        result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    require(result == child && WIFEXITED(status), "service-exit");
    int code = WEXITSTATUS(status);
    require(code == 0 || code == 1, "service-status");
    printf("RANDOM_SEED_FAULT_SERVICE mode=%s status=%d pid=%d\n", operation, code, child);
    return code;
}

static void seed(unsigned char output[32], struct stat* status, int allow_checkpoint) {
    int fd = open("/mnt/seed/random/seed", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    require(fd >= 0, "seed-open");
    require(fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
                (status->st_mode & 07777) == 0600 && status->st_uid == 0 && status->st_gid == 0 &&
                status->st_size == 32 && status->st_nlink >= 1 &&
                status->st_nlink <= (allow_checkpoint ? 2 : 1),
            "seed-metadata");
    size_t done = 0;
    while (done < 32) {
        ssize_t count = read(fd, output + done, 32 - done);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "seed-read");
        done += count;
    }
    require(close(fd) == 0, "seed-close");
}

static void report_seed(const char* state, const unsigned char data[32],
                        const struct stat* status) {
    printf("RANDOM_SEED_FAULT_PAYLOAD state=%s inode=%lu links=%lu value=", state,
           (unsigned long)status->st_ino, (unsigned long)status->st_nlink);
    for (unsigned i = 0; i < 32; i++)
        printf("%02x", data[i]);
    puts("");
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    require(argc == 2 && (!strcmp(argv[1], "io") || !strcmp(argv[1], "full")), "arguments");
    require(mount("/dev/vda", "/mnt/seed", "ext2", 0, NULL) == 0, "ext2-mount");
    int random = open("/dev/random", O_RDONLY | O_CLOEXEC);
    int bits = -1;
    require(random >= 0 && ioctl(random, 0x80045200U, &bits) == 0 && close(random) == 0 &&
                bits == 256,
            "initialized-source");
    unsigned char original[32], after[32], refreshed[32];
    struct stat before_status, after_status, refreshed_status;
    seed(original, &before_status, 0);
    report_seed("original", original, &before_status);
    puts("RANDOM_SEED_FAULT_ROTATION_BEGIN");
    int failed = service("rotate");
    seed(after, &after_status, 1);
    if (failed) {
        require(!memcmp(original, after, 32) && before_status.st_ino == after_status.st_ino,
                "failure-preserves-complete-seed");
        report_seed("preserved", after, &after_status);
    } else {
        require(memcmp(original, after, 32), "committed-replacement");
        report_seed("committed", after, &after_status);
    }
    if (!strcmp(argv[1], "full")) {
        require(failed == 1, "full-volume-rejects-rotation");
        require(unlink("/mnt/seed/fill") == 0, "release-full-volume");
    }
    require(service("load") == 0, "recover-service");
    seed(refreshed, &refreshed_status, 0);
    require(!memcmp(after, refreshed, 32) && after_status.st_ino == refreshed_status.st_ino,
            "recovery-preserves-complete-seed");
    require(service("rotate") == 0, "retry-rotation");
    seed(refreshed, &refreshed_status, 0);
    require(memcmp(after, refreshed, 32), "retry-replaces-payload");
    report_seed("retry", refreshed, &refreshed_status);
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fd >= 0 && fsync(fd) == 0 && close(fd) == 0, "recovered-directory-sync");
    require(umount("/mnt/seed") == 0, "ext2-unmount");
    printf("RANDOM_SEED_FAULT_PASS linkage=%s mode=%s first_status=%d\n", RANDOM_LINKAGE, argv[1],
           failed);
    return 0;
}
