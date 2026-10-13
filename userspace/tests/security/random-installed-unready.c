// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "INSTALLED_RANDOM_FAIL line=%d errno=%d expression=%s\n", __LINE__,    \
                    errno, #expression);                                                           \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int absent(const char* path) {
    struct stat value;
    return lstat(path, &value) < 0 && errno == ENOENT;
}

static int observe(void) {
    // A fixed, root-owned fixture observer supplies no command interface. The
    // installed init and random-seed bytes and their retry policy are retained.
    struct timespec before, after, interval = {8, 0};
    CHECK(!getuid() && !geteuid() && !getgid() && !getegid());
    int lock = open("/run/random-installed-observer.lock",
                    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat value;
    CHECK(lock >= 0 && fstat(lock, &value) == 0 && S_ISREG(value.st_mode) &&
          (value.st_mode & 07777) == 0600 && !value.st_uid && !value.st_gid && value.st_nlink == 1);
    if (flock(lock, LOCK_EX | LOCK_NB) < 0) {
        CHECK(errno == EWOULDBLOCK || errno == EAGAIN);
        close(lock);
        return 0;
    }
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    while (nanosleep(&interval, &interval) < 0)
        CHECK(errno == EINTR);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK(after.tv_sec > before.tv_sec + 8 ||
          (after.tv_sec == before.tv_sec + 8 && after.tv_nsec >= before.tv_nsec));
    CHECK(lstat("/var/lib/axiom64/random", &value) == 0 && S_ISDIR(value.st_mode) &&
          (value.st_mode & 07777) == 0700 && !value.st_uid && !value.st_gid);
    CHECK(absent("/var/lib/axiom64/random/seed"));
    unsigned char byte = 0xa5;
    CHECK(getrandom(&byte, 1, GRND_NONBLOCK) == -1 && errno == EAGAIN && byte == 0xa5);
    CHECK(absent("/etc/axiom64/accounts/current"));
    CHECK(absent("/tmp/.X11-unix/X0"));
    puts("INSTALLED_RANDOM_UNREADY_SINGLETON lock=1");
    puts("INSTALLED_RANDOM_UNREADY_OBSERVER private_directory=1 seed_absent=1 initialized_denied=1 "
         "accounts_unpublished=1 x11_absent=1 observation_seconds=8");
    puts("INSTALLED_RANDOM_CHECK unready");
    fflush(stdout);
    CHECK(reboot(RB_POWER_OFF) == 0);
    return 1;
}

int main(void) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child)
        return observe();
    execl("/sbin/network-manager-installed", "network-manager", (char*)NULL);
    perror("INSTALLED_RANDOM_FAIL network manager exec");
    return 1;
}
