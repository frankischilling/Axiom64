// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/init/main.c
 * @brief   Initial userspace process.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Mounts filesystems, starts configured services, and supervises child
 * processes.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include "console.h"
#include "seed_records.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char debug_network[] = "/etc/axiom64-debug-network";
static const char debug_ssh_config[] = "/etc/ssh/sshd_config.debug";

static pid_t network(int debug) {
    pid_t child = fork();
    if (!child) {
        int input = open("/dev/null", O_RDONLY);
        if (input >= 0) {
            dup2(input, 0);
            close(input);
        }
        if (debug && access(debug_network, F_OK) == 0)
            execl("/sbin/network-manager", "network-manager", "--saved", debug_network, (char*)0);
        else
            execl("/sbin/network-manager", "network-manager", (char*)0);
        perror("init: network manager exec");
        _exit(1);
    }
    return child;
}

static pid_t start_service(const char* path, int own_session) {
    pid_t child = fork();
    if (!child) {
        int input = open("/dev/null", O_RDONLY);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0)
            _exit(126);
        if (input != STDIN_FILENO)
            close(input);
        if (own_session && setsid() < 0)
            _exit(126);
        char* const arguments[] = {(char*)path, NULL};
        char* const environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/", NULL};
        execve(arguments[0], arguments, environment);
        perror(path);
        _exit(127);
    }
    if (child < 0)
        perror(path);
    return child;
}

static int debug_ssh_configured(void) {
    struct stat config;
    return lstat(debug_ssh_config, &config) == 0 && S_ISREG(config.st_mode) && config.st_uid == 0 &&
           (config.st_mode & 0777) == 0600 && access("/usr/sbin/sshd", X_OK) == 0;
}

static pid_t start_debug_ssh(void) {
    pid_t child = fork();
    if (!child) {
        int input = open("/dev/null", O_RDONLY);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0)
            _exit(126);
        if (input != STDIN_FILENO)
            close(input);
        char* const arguments[] = {"/usr/sbin/sshd",
                                   "-D",
                                   "-e",
                                   "-f",
                                   (char*)debug_ssh_config,
                                   "-o",
                                   "AuthenticationMethods=publickey",
                                   "-o",
                                   "PubkeyAuthentication=yes",
                                   "-o",
                                   "PasswordAuthentication=no",
                                   "-o",
                                   "KbdInteractiveAuthentication=no",
                                   "-o",
                                   "PermitRootLogin=no",
                                   "-o",
                                   "DisableForwarding=yes",
                                   NULL};
        char* const environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/", NULL};
        execve(arguments[0], arguments, environment);
        perror("init: debug SSH exec");
        _exit(127);
    }
    if (child < 0)
        perror("init: debug SSH fork");
    return child;
}

static int monotonic(struct timespec* now) {
    if (clock_gettime(CLOCK_MONOTONIC, now) < 0) {
        perror("init: monotonic clock");
        return -1;
    }
    return 0;
}

static int enabled(const char* name) {
    const char* value = getenv(name);
    return value && !strcmp(value, "1");
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
        const int debug = enabled("AXIOM64_DEBUG_SSH");
        pid_t manager = network(debug);
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
        const char* bus_path = "/usr/libexec/axiom64-system-bus";
        const int bus_installed = access(bus_path, X_OK) == 0;
        struct timespec bus_retry = retry;
        pid_t bus = bus_installed ? start_service(bus_path, 0) : -1;
        const int text_console = enabled("AXIOM64_TEXT_CONSOLE");
        const char* display_path = "/usr/libexec/axiom64-display-manager";
        const int use_display_manager = !text_console && access(display_path, X_OK) == 0 &&
                                        access("/etc/axiom64/console-desktop", F_OK) != 0;
        struct timespec display_retry = retry;
        pid_t display = use_display_manager ? start_service(display_path, 1) : -1;
        pid_t ssh = -1;
        struct timespec ssh_retry = retry;
        const int ssh_enabled = debug && debug_ssh_configured();
        if (debug && !ssh_enabled)
            fputs("Debug SSH needs a root-owned mode-0600 sshd_config.debug and OpenSSH.\n",
                  stderr);
        bus_retry.tv_sec++;
        seed_retry.tv_sec++;
        retry.tv_sec++;
        struct init_console console;
        struct timespec console_start;
        const char* service_accounts = use_display_manager ? "desktop"
                                       : bus_installed     ? "bus"
                                                           : "none";
        if (monotonic(&console_start) < 0 ||
            init_console_initialize(&console, &console_start, text_console || use_display_manager,
                                    service_accounts) < 0) {
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
            } else if (child > 0 && child == bus) {
                fprintf(stderr, "System bus exited status=%d. Retrying in one second.\n", status);
                bus = -1;
                if (monotonic(&bus_retry) < 0)
                    return 1;
                bus_retry.tv_sec++;
            } else if (child > 0 && child == display) {
                if (kill(-display, SIGKILL) < 0 && errno != ESRCH)
                    perror("init: display manager cleanup");
                fprintf(stderr, "Display manager exited status=%d. Retrying in five seconds.\n",
                        status);
                display = -1;
                if (monotonic(&display_retry) < 0)
                    return 1;
                display_retry.tv_sec += 5;
            } else if (child > 0 && child == ssh) {
                fprintf(stderr, "Debug SSH exited status=%d. Retrying.\n", status);
                ssh = -1;
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
                manager = network(debug);
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
            if (bus_installed && bus < 0 &&
                (now.tv_sec > bus_retry.tv_sec ||
                 (now.tv_sec == bus_retry.tv_sec && now.tv_nsec >= bus_retry.tv_nsec))) {
                bus = start_service(bus_path, 0);
                bus_retry = now;
                bus_retry.tv_sec++;
            }
            if (use_display_manager && display < 0 &&
                (now.tv_sec > display_retry.tv_sec ||
                 (now.tv_sec == display_retry.tv_sec && now.tv_nsec >= display_retry.tv_nsec))) {
                display = start_service(display_path, 1);
                display_retry = now;
                display_retry.tv_sec += 5;
            }
            if (ssh_enabled && seeded && ssh < 0 &&
                (now.tv_sec > ssh_retry.tv_sec ||
                 (now.tv_sec == ssh_retry.tv_sec && now.tv_nsec >= ssh_retry.tv_nsec))) {
                if (debug_ssh_configured())
                    ssh = start_debug_ssh();
                ssh_retry = now;
                ssh_retry.tv_sec += 5;
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
