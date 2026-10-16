// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "console.h"
#include "seed_records.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t network(void) {
    pid_t child = fork();
    if (!child) {
        int input = open("/dev/null", O_RDONLY);
        if (input >= 0) {
            dup2(input, 0);
            close(input);
        }
        execl("/sbin/network-manager", "network-manager", (char*)0);
        perror("init: network manager exec");
        _exit(1);
    }
    return child;
}

static int monotonic(struct timespec* now) {
    if (clock_gettime(CLOCK_MONOTONIC, now) < 0) {
        perror("init: monotonic clock");
        return -1;
    }
    return 0;
}

static unsigned long long milliseconds(const struct timespec* now) {
    return (unsigned long long)now->tv_sec * 1000 + (unsigned long long)now->tv_nsec / 1000000;
}

static void spawned(pid_t child, const struct timespec* now) {
    printf("INIT_MANAGER_SPAWN pid=%d monotonic_ms=%llu\n", child, milliseconds(now));
    fflush(stdout);
}

static pid_t seed_service(const struct timespec* now) {
    pid_t child = fork();
    if (!child) {
        int input = open("/dev/null", O_RDONLY);
        if (input >= 0) {
            dup2(input, 0);
            close(input);
        }
        execl("/sbin/random-seed", "random-seed", "boot", "--nonblock", (char*)0);
        perror("init: random seed service exec");
        _exit(1);
    }
    if (child < 0)
        perror("init: random seed service fork");
    else {
        init_seed_spawned_record(child, milliseconds(now));
    }
    return child;
}

int main(void) {
    const char* test = getenv("AXIOM64_TEST");
    const char* suite = getenv("AXIOM64_SUITE");
    if (test && *test == '1') {
        const char* script = suite && !strcmp(suite, "network")   ? "/etc/net-test.sh"
                             : suite && !strcmp(suite, "storage") ? "/etc/storage-test.sh"
                             : suite && !strcmp(suite, "root")    ? "/etc/root-test.sh"
                             : suite && !strcmp(suite, "ext2")    ? "/etc/ext2-test.sh"
                             : suite && !strcmp(suite, "threads") ? "/etc/thread-test.sh"
                             : suite && !strcmp(suite, "desktop") ? "/etc/desktop-test.sh"
                                                                  : "/etc/boot-test.sh";
        execl("/bin/busybox", "busybox", "sh", script, (char*)0);
    } else {
        puts("Axiom64. Create an administrator on first boot, then log in to start a session.");
        pid_t manager = network();
        struct timespec retry;
        if (monotonic(&retry) < 0)
            return 1;
        if (manager < 0)
            perror("init: network manager fork");
        else
            spawned(manager, &retry);
        struct timespec seed_retry = retry;
        pid_t seeder = seed_service(&seed_retry);
        int seeded = 0;
        seed_retry.tv_sec++;
        retry.tv_sec++;
        struct init_console console;
        struct timespec console_start;
        if (monotonic(&console_start) < 0 ||
            init_console_initialize(&console, &console_start) < 0) {
            perror("init: authenticated console setup");
            return 1;
        }
        for (;;) {
            int status;
            pid_t child = waitpid(-1, &status, WNOHANG);
            if (child < 0) {
                if (errno == EINTR)
                    continue;
                if (errno != ECHILD) {
                    perror("init: wait");
                    return 1;
                }
                child = 0;
            }
            if (child > 0 && child == manager) {
                printf("Network manager exited status=%d; retrying after one second.\n", status);
                manager = -1;
                if (monotonic(&retry) < 0)
                    return 1;
                printf("INIT_MANAGER_REAP pid=%d status=%d monotonic_ms=%llu\n", child, status,
                       milliseconds(&retry));
                fflush(stdout);
                retry.tv_sec++;
            } else if (child > 0 && child == seeder) {
                seeder = -1;
                if (monotonic(&seed_retry) < 0)
                    return 1;
                init_seed_reaped_record(child, status, milliseconds(&seed_retry));
                seeded = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                seed_retry.tv_sec++;
            }
            struct timespec now;
            if (monotonic(&now) < 0)
                return 1;
            if (init_console_update(&console, child, child > 0 ? status : 0, &now) < 0) {
                perror("init: authenticated console recovery");
                return 1;
            }
            if (manager < 0 && (now.tv_sec > retry.tv_sec ||
                                (now.tv_sec == retry.tv_sec && now.tv_nsec >= retry.tv_nsec))) {
                manager = network();
                if (manager < 0)
                    perror("init: network manager fork");
                else
                    spawned(manager, &now);
                retry = now;
                retry.tv_sec++;
            }
            if (!seeded && seeder < 0 &&
                (now.tv_sec > seed_retry.tv_sec ||
                 (now.tv_sec == seed_retry.tv_sec && now.tv_nsec >= seed_retry.tv_nsec))) {
                seeder = seed_service(&now);
                seed_retry = now;
                seed_retry.tv_sec++;
            }
            if (!child) {
                struct timespec interval = {0, 100000000};
                if (nanosleep(&interval, NULL) < 0 && errno != EINTR) {
                    perror("init: wait interval");
                    return 1;
                }
            }
        }
    }
    perror("init: exec");
    return 1;
}
