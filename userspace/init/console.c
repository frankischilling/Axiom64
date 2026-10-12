// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "console.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

static unsigned long long milliseconds(const struct timespec* time) {
    return (unsigned long long)time->tv_sec * 1000 + (unsigned long long)time->tv_nsec / 1000000;
}

static void record(const char* event, pid_t child, int status, const struct timespec* time) {
    char bytes[160];
    int size =
        snprintf(bytes, sizeof(bytes), "\nINIT_CONSOLE_%s pid=%d status=%d monotonic_ms=%llu\n",
                 event, (int)child, status, milliseconds(time));
    if (size > 0 && (size_t)size < sizeof(bytes)) {
        fflush(stdout);
        ssize_t written = write(1, bytes, (size_t)size);
        (void)written;
    }
}

static int restore(const struct init_console* console) {
    if (fcntl(0, F_SETFL, console->flags) < 0 || tcsetattr(0, TCSAFLUSH, &console->original) < 0)
        return -1;
    return 0;
}

static int due(const struct timespec* now, const struct timespec* deadline) {
    return now->tv_sec > deadline->tv_sec ||
           (now->tv_sec == deadline->tv_sec && now->tv_nsec >= deadline->tv_nsec);
}

int init_console_update(struct init_console* console, pid_t reaped, int status,
                        const struct timespec* now) {
    if (reaped > 0 && reaped == console->pid) {
        // The console and its privileged password/login workers share this
        // group. Retire workers left behind by an abruptly killed supervisor.
        if (kill(-console->pid, SIGKILL) < 0 && errno != ESRCH)
            return -1;
        if (restore(console) < 0)
            return -1;
        record("REAP", console->pid, status, now);
        console->pid = -1;
        console->retry = *now;
        console->retry.tv_sec++;
    }
    if (console->pid > 0 || !due(now, &console->retry))
        return 0;
    if (restore(console) < 0)
        return -1;
    console->pid = fork();
    if (!console->pid) {
        static const int defaults[] = {SIGINT,  SIGQUIT, SIGHUP,  SIGTERM,
                                       SIGCHLD, SIGTTOU, SIGTTIN, SIGTSTP};
        struct sigaction action = {.sa_handler = SIG_DFL};
        sigemptyset(&action.sa_mask);
        for (size_t index = 0; index < sizeof(defaults) / sizeof(*defaults); index++)
            if (sigaction(defaults[index], &action, NULL) < 0)
                _exit(126);
        sigset_t mask;
        sigemptyset(&mask);
        if (sigprocmask(SIG_SETMASK, &mask, NULL) < 0 || setsid() < 0 || ioctl(0, TIOCSCTTY, 1) < 0)
            _exit(126);
        execl("/sbin/account-console", "account-console", (char*)NULL);
        perror("init: authenticated console exec");
        _exit(127);
    }
    console->retry = *now;
    console->retry.tv_sec++;
    if (console->pid < 0) {
        perror("init: authenticated console fork");
        return 0;
    }
    record("SPAWN", console->pid, 0, now);
    return 0;
}

int init_console_initialize(struct init_console* console, const struct timespec* now) {
    *console = (struct init_console){.pid = -1, .retry = *now};
    console->flags = fcntl(0, F_GETFL);
    if (console->flags < 0 || tcgetattr(0, &console->original) < 0)
        return -1;
    // Init can restore the physical terminal while its former foreground group
    // is being reaped. Children reset this inherited disposition before exec.
    struct sigaction action = {.sa_handler = SIG_IGN};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTTOU, &action, NULL) < 0)
        return -1;
    return init_console_update(console, 0, 0, now);
}
