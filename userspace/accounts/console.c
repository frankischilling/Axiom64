// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "database.h"
#include "protected.h"
#include "../desktop/seat.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;

static int failed(int error) {
    errno = error;
    return -1;
}

static void stop(int number) {
    stopped = number;
}

static int pause_retry(void) {
    struct timespec delay = {1, 0};
    while (!stopped && nanosleep(&delay, &delay) < 0)
        if (errno != EINTR)
            return -1;
    return stopped ? failed(ECANCELED) : 0;
}

static int worker_check(const char* executable) {
    char path[PATH_MAX];
    size_t length = strlen(executable);
    if (!length || length >= sizeof(path) || executable[0] != '/')
        return failed(EINVAL);
    memcpy(path, executable, length + 1);
    char* name = strrchr(path, '/');
    if (!name || !name[1])
        return failed(EINVAL);
    *name++ = 0;
    int parent = account_directory_open(*path ? path : "/", 0755, 0);
    if (parent < 0)
        return -1;
    int descriptor = account_executable_open(parent, name);
    int error = descriptor < 0 ? errno : 0;
    if (descriptor >= 0)
        close(descriptor);
    close(parent);
    return error ? failed(error) : 0;
}

static int public_name(int terminal, char name[ACCOUNT_NAME_MAX + 1]) {
    if (dprintf(terminal, "Administrator name: ") < 0)
        return -1;
    size_t used = 0;
    int invalid = 0;
    for (;;) {
        if (stopped)
            return failed(ECANCELED);
        char byte;
        ssize_t count = read(terminal, &byte, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EIO);
        if (byte == '\n')
            break;
        if (!byte || byte == '\r' || used == ACCOUNT_NAME_MAX)
            invalid = 1;
        else if (!invalid)
            name[used++] = byte;
    }
    name[used] = 0;
    return invalid || !account_name_valid(name) ? failed(EINVAL) : 0;
}

static int run(char* const arguments[], int terminal, const struct termios* original) {
    if (worker_check(arguments[0]) < 0)
        return -1;
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (!child) {
        // Keep the worker in the console's group so init can retire the entire
        // physical-terminal frontend if its supervisor is forcibly killed.
        static const int defaults[] = {SIGINT, SIGQUIT, SIGHUP, SIGTERM, SIGCHLD};
        struct sigaction action = {.sa_handler = SIG_DFL};
        sigemptyset(&action.sa_mask);
        for (size_t i = 0; i < sizeof(defaults) / sizeof(*defaults); i++)
            if (sigaction(defaults[i], &action, NULL) < 0)
                _exit(126);
        sigset_t mask;
        sigemptyset(&mask);
        if (sigprocmask(SIG_SETMASK, &mask, NULL) < 0 || setenv("TERM", "vt100", 1) < 0)
            _exit(126);
        execv(arguments[0], arguments);
        perror("account-console: authentication exec");
        _exit(127);
    }
    int status = 0, error = 0;
    unsigned attempts = 0;
    for (;;) {
        pid_t result = waitpid(child, &status, stopped ? WNOHANG : 0);
        if (result == child)
            break;
        if (result < 0 && errno != EINTR) {
            error = errno;
            break;
        }
        if (stopped) {
            kill(child, attempts < 20 ? SIGTERM : SIGKILL);
            struct timespec tick = {0, 100000000};
            while (nanosleep(&tick, &tick) < 0 && errno == EINTR) {
            }
            attempts++;
        }
    }
    if (tcsetattr(terminal, TCSAFLUSH, original) < 0 && !error)
        error = errno;
    if (error)
        return failed(error);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

int main(int argc, char** argv) {
    if (getuid() || geteuid() || getegid()) {
        fputs("account-console: root supervision is required\n", stderr);
        return 1;
    }
    const char *database = "/etc/axiom64/accounts", *records = "/var/log/axiom64/login";
    const char *executable = "/usr/bin/account-access", *homes = "/home", *shell = "/bin/bash";
    int graphical = 0;
    for (int index = 1; index < argc; index += 2) {
        if (index + 1 == argc)
            return 2;
        if (!strcmp(argv[index], "--database"))
            database = argv[index + 1];
        else if (!strcmp(argv[index], "--records"))
            records = argv[index + 1];
        else if (!strcmp(argv[index], "--access"))
            executable = argv[index + 1];
        else if (!strcmp(argv[index], "--home-root"))
            homes = argv[index + 1];
        else if (!strcmp(argv[index], "--shell"))
            shell = argv[index + 1];
        else if (!strcmp(argv[index], "--session")) {
            if (strcmp(argv[index + 1], "desktop") && strcmp(argv[index + 1], "shell"))
                return 2;
            graphical = !strcmp(argv[index + 1], "desktop");
        } else
            return 2;
    }
    if (tcgetsid(0) != getsid(0) || tcgetpgrp(0) != getpgrp()) {
        fputs("account-console: a foreground controlling terminal is required\n", stderr);
        return 1;
    }
    // Init correctly supplies read-only stdin and write-only output streams.
    // Prompts and input need a separate read/write controlling-terminal handle.
    int terminal = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    struct termios original = {0};
    if (terminal < 0 || tcgetattr(terminal, &original) < 0 || tcgetsid(terminal) != getsid(0) ||
        tcgetpgrp(terminal) != getpgrp() || !(original.c_lflag & ICANON)) {
        fputs("account-console: a foreground controlling terminal is required\n", stderr);
        return 1;
    }
    if (setgroups(0, NULL) < 0 || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0 || clearenv() < 0)
        return 1;
    umask(077);
    struct sigaction action = {.sa_handler = SIG_IGN};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) < 0 || sigaction(SIGQUIT, &action, NULL) < 0)
        return 1;
    action.sa_handler = stop;
    if (sigaction(SIGHUP, &action, NULL) < 0 || sigaction(SIGTERM, &action, NULL) < 0)
        return 1;
    int error = 0;
    if (graphical) {
        for (unsigned attempt = 0; !stopped; attempt++) {
            if (desktop_seat_recover() == 0)
                break;
            if (errno != EBUSY || attempt == 9) {
                error = errno;
                break;
            }
            if (pause_retry() < 0) {
                error = errno;
                break;
            }
        }
    }
    while (!stopped && !error) {
        struct account_database* db = NULL;
        if (account_database_begin(database, 1, &db) < 0) {
            error = errno;
            fputs("Accounts unavailable; authentication is blocked.\n", stderr);
            break;
        }
        int fresh = account_database_fresh(db);
        // Never fork an authentication worker while retaining the database lock.
        account_database_end(db);
        char name[ACCOUNT_NAME_MAX + 1], home[PATH_MAX];
        if (fresh) {
            dprintf(terminal, "Axiom64 first boot: create an administrator.\n");
            if (public_name(terminal, name) < 0) {
                if (errno != EINVAL) {
                    error = errno;
                    break;
                }
                dprintf(terminal, "Invalid administrator name.\n");
                if (pause_retry() < 0)
                    break;
                continue;
            }
            if (snprintf(home, sizeof(home), "%s/%s", homes, name) >= (int)sizeof(home)) {
                error = ENAMETOOLONG;
                break;
            }
        }
        char* arguments[] = {(char*)executable,
                             "--database",
                             (char*)database,
                             "--records",
                             (char*)records,
                             fresh       ? "provision"
                             : graphical ? "desktop"
                                         : "login",
                             fresh ? name : NULL,
                             fresh ? home : NULL,
                             fresh ? (char*)shell : NULL,
                             NULL};
        int result = run(arguments, terminal, &original);
        if (result < 0) {
            error = errno;
            break;
        }
        if (fresh && !result)
            dprintf(terminal, "Administrator created. Please log in.\n");
        if (result && pause_retry() < 0)
            break;
    }
    if (tcsetattr(terminal, TCSAFLUSH, &original) < 0 && !error)
        error = errno;
    close(terminal);
    if (error) {
        errno = error;
        perror("account-console");
    }
    return error ? 1 : 0;
}
