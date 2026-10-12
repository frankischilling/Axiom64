// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RANDOM_LINKAGE
#define RANDOM_LINKAGE "static"
#endif

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "RANDOM_SEED_CRASH_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    require(argc == 4 && (!strcmp(argv[1], "stop") || !strcmp(argv[1], "recover")), "arguments");
    int recovering = !strcmp(argv[1], "recover");
    int existing = !strcmp(argv[3], "present");
    require(existing || !strcmp(argv[3], "absent"), "initial-seed");
    require(mount("/dev/vda", "/mnt/seed", "ext2", 0, recovering ? "recovery=check" : NULL) == 0,
            "mount");
    pid_t child = fork();
    require(child >= 0, "fork");
    if (!child) {
        if (!recovering)
            require(setenv("AXIOM64_SEED_CRASH_POINT", argv[2], 1) == 0, "select-boundary");
        const char* service = recovering ? "/sbin/random-seed" : "/sbin/random-seed-stop";
        execl(service, "random-seed", recovering ? "load" : "rotate", "--directory",
              "/mnt/seed/random", "--nonblock", (char*)0);
        _exit(127);
    }
    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, recovering ? 0 : WUNTRACED);
    } while (waited < 0 && errno == EINTR);
    require(waited == child, "wait");
    if (!recovering) {
        require(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP, "actual-service-stop");
        printf("RANDOM_SEED_CRASH_BOUNDARY point=%s child=%d status=%d\n", argv[2], child, status);
        for (;;)
            pause();
    }
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "recovery-service");
    int random = open("/dev/random", O_RDONLY | O_CLOEXEC), bits = -1;
    require(random >= 0 && ioctl(random, 0x80045200U, &bits) == 0 && bits == 0 &&
                close(random) == 0,
            "recovery-does-not-credit-seed");
    unsigned char bytes[32];
    errno = 0;
    require(getrandom(bytes, sizeof(bytes), GRND_NONBLOCK) == -1 && errno == EAGAIN,
            "recovery-remains-unready");
    int replaced = !strcmp(argv[2], "published") || !strcmp(argv[2], "committed") ||
                   !strcmp(argv[2], "cleanup-unlinked");
    int present = existing || replaced;
    struct stat metadata;
    if (present) {
        int fd = open("/mnt/seed/random/seed", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        require(fd >= 0 && fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                    (metadata.st_mode & 07777) == 0600 && metadata.st_uid == 0 &&
                    metadata.st_gid == 0 && metadata.st_nlink == 1 && metadata.st_size == 32,
                "recovered-metadata");
        require(read(fd, bytes, sizeof(bytes)) == sizeof(bytes) && close(fd) == 0,
                "recovered-payload");
        if (!replaced)
            for (unsigned i = 0; i < sizeof(bytes); i++)
                require(bytes[i] == i, "original-payload");
        printf("RANDOM_SEED_CRASH_PAYLOAD inode=%lu value=", (unsigned long)metadata.st_ino);
        for (unsigned i = 0; i < sizeof(bytes); i++)
            printf("%02x", bytes[i]);
        puts("");
    } else {
        require(lstat("/mnt/seed/random/seed", &metadata) < 0 && errno == ENOENT,
                "missing-seed-remains-missing");
    }
    DIR* directory = opendir("/mnt/seed/random");
    require(directory != NULL, "directory-open");
    unsigned entries = 0;
    errno = 0;
    struct dirent* entry;
    while ((entry = readdir(directory))) {
        require(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
                    !strcmp(entry->d_name, "lock") || !strcmp(entry->d_name, "unrelated") ||
                    (present && !strcmp(entry->d_name, "seed")),
                "recovered-directory-entries");
        entries++;
    }
    require(errno == 0 && entries == (present ? 5U : 4U) && closedir(directory) == 0,
            "complete-directory");
    int unrelated = open("/mnt/seed/random/unrelated", O_RDONLY | O_CLOEXEC);
    char sentinel[4];
    require(unrelated >= 0 && read(unrelated, sentinel, sizeof(sentinel)) == 4 &&
                !memcmp(sentinel, "keep", 4) && close(unrelated) == 0,
            "unrelated-file-preserved");
    require(umount("/mnt/seed") == 0, "unmount");
    printf("RANDOM_SEED_CRASH_PASS linkage=%s point=%s initial=%s present=%d credit=0\n",
           RANDOM_LINKAGE, argv[2], argv[3], present);
    return 0;
}
