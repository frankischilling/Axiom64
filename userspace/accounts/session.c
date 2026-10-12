// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "session.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static const int caught[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGWINCH, SIGCHLD, SIGPIPE};
static volatile sig_atomic_t cancelled, resized;

static int failed(int error) {
    errno = error;
    return -1;
}

static void notified(int number) {
    if (number == SIGWINCH)
        resized = 1;
    else if (number != SIGCHLD && !cancelled)
        cancelled = number;
}

static int transfer(int fd, void* bytes, size_t size, int writing) {
    size_t done = 0;
    while (done < size) {
        if (cancelled)
            return failed(ECANCELED);
        ssize_t count = writing ? write(fd, (char*)bytes + done, size - done)
                                : read(fd, (char*)bytes + done, size - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count < 0 ? errno : EIO);
        done += (size_t)count;
    }
    return 0;
}

static int child_descriptors(int ready, int go) {
    int first = fcntl(ready, F_DUPFD_CLOEXEC, 5);
    if (first < 0)
        return -1;
    int second = fcntl(go, F_DUPFD_CLOEXEC, 5);
    if (second < 0) {
        close(first);
        return -1;
    }
    int error = (dup2(first, 3) < 0 || dup2(second, 4) < 0) ? errno : 0;
    close(first);
    close(second);
    if (error)
        return failed(error);
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 5u, UINT32_MAX, 0u) == 0)
        return 0;
    if (errno != ENOSYS && errno != EINVAL)
        return -1;
#endif
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0 || limit.rlim_cur > 1048576)
        return failed(EOVERFLOW);
    for (unsigned fd = 5; fd < limit.rlim_cur; fd++)
        close((int)fd);
    return 0;
}

static void child(const struct account_profile* profile, int slave, int ready, int go,
                  const char* terminal_type, unsigned terminal_streams, char* const command[]) {
    int report = fcntl(ready, F_DUPFD_CLOEXEC, 5);
    int allowed_fd = fcntl(go, F_DUPFD_CLOEXEC, 5);
    int terminal_fd = fcntl(slave, F_DUPFD_CLOEXEC, 5);
    int error = report < 0 || allowed_fd < 0 || terminal_fd < 0 ? errno : 0;
    if (!error && (setsid() < 0 || ioctl(terminal_fd, TIOCSCTTY, 0) < 0))
        error = errno;
    for (unsigned fd = 0; !error && fd < 3; fd++)
        if ((terminal_streams & (1u << fd)) && dup2(terminal_fd, (int)fd) < 0)
            error = errno;
    if (!error) {
        if (child_descriptors(report, allowed_fd) < 0)
            error = errno;
        else
            report = 3;
    }
    if (!error) {
        for (int number = 1; number < NSIG; number++)
            if (number != SIGKILL && number != SIGSTOP && signal(number, SIG_DFL) == SIG_ERR &&
                errno != EINVAL) {
                error = errno;
                break;
            }
        sigset_t empty;
        sigemptyset(&empty);
        if (sigprocmask(SIG_SETMASK, &empty, NULL) < 0)
            error = errno;
    }
    if (!error && (account_profile_environment(profile, terminal_type) < 0 ||
                   account_profile_enter(profile, 0) < 0))
        error = errno;
    umask(077);
    if (!error && chdir(profile->home) < 0)
        error = errno;
    if (report < 0)
        report = ready;
    if (transfer(report, &error, sizeof(error), 1) < 0 || error)
        _exit(126);
    close(3);
    char allowed;
    if (transfer(4, &allowed, 1, 0) < 0 || allowed != 'x')
        _exit(126);
    close(4);
    execvp(command[0], command);
    perror("account session: exec");
    _exit(127);
}

struct buffer {
    char bytes[8192];
    size_t begin, end;
};

static int fill(int fd, struct buffer* buffer) {
    if (buffer->begin) {
        memmove(buffer->bytes, buffer->bytes + buffer->begin, buffer->end - buffer->begin);
        buffer->end -= buffer->begin;
        buffer->begin = 0;
    }
    if (buffer->end == sizeof(buffer->bytes))
        return 1;
    ssize_t count = read(fd, buffer->bytes + buffer->end, sizeof(buffer->bytes) - buffer->end);
    if (count > 0) {
        buffer->end += (size_t)count;
        return 1;
    }
    return count == 0 || (count < 0 && errno == EIO) ? 0
           : errno == EAGAIN || errno == EINTR       ? 1
                                                     : -1;
}

static int drain(int fd, struct buffer* buffer) {
    ssize_t count = write(fd, buffer->bytes + buffer->begin, buffer->end - buffer->begin);
    if (count > 0) {
        buffer->begin += (size_t)count;
        if (buffer->begin == buffer->end)
            buffer->begin = buffer->end = 0;
        return 0;
    }
    return count < 0 && (errno == EAGAIN || errno == EINTR) ? 0 : failed(count < 0 ? errno : EIO);
}

static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    return now.tv_sec * INT64_C(1000) + now.tv_nsec / 1000000;
}

static void signal_child(int master, pid_t child, int signal) {
    pid_t group = tcgetpgrp(master);
    if (group > 0 && tcgetsid(master) == child)
        kill(-group, signal);
    kill(child, signal);
}

static int relay(int terminal, int master, pid_t child, int* status, int* reaped) {
    struct buffer input = {{0}, 0, 0}, output = {{0}, 0, 0};
    int finished = 0, reading = 1, master_open = 1;
    int64_t deadline = -1;
    for (;;) {
        if (!finished) {
            pid_t result = waitpid(child, status, WNOHANG);
            if (result == child) {
                finished = 1;
                *reaped = 1;
            } else if (result < 0 && errno != EINTR)
                return -1;
        }
        if (resized) {
            resized = 0;
            struct winsize size;
            if (ioctl(terminal, TIOCGWINSZ, &size) == 0)
                ioctl(master, TIOCSWINSZ, &size);
        }
        if (cancelled && !finished && deadline < 0) {
            signal_child(master, child, cancelled);
            signal_child(master, child, SIGCONT);
            deadline = milliseconds();
            if (deadline < 0)
                return -1;
            deadline += 2000;
            reading = 0;
        }
        if (!finished && deadline >= 0) {
            int64_t now = milliseconds();
            if (now < 0)
                return -1;
            if (now >= deadline) {
                signal_child(master, child, SIGKILL);
                deadline = INT64_MAX;
            }
        }
        if (finished) {
            reading = 0;
            if (master_open && output.end - output.begin < sizeof(output.bytes)) {
                size_t previous = output.end - output.begin;
                int result = fill(master, &output);
                if (result < 0)
                    return -1;
                if (!result || previous == output.end - output.begin)
                    master_open = 0;
            }
            if (!master_open && !output.end)
                return 0;
        } else if (!master_open && output.end - output.begin < sizeof(output.bytes)) {
            size_t previous = output.end - output.begin;
            int result = fill(master, &output);
            if (result < 0)
                return -1;
            if (result && previous != output.end - output.begin)
                master_open = 1;
        }
        struct pollfd items[2] = {
            {terminal,
             (short)((reading && input.end - input.begin < sizeof(input.bytes) ? POLLIN : 0) |
                     (output.end ? POLLOUT : 0)),
             0},
            {master_open ? master : -1,
             (short)((master_open && output.end - output.begin < sizeof(output.bytes) ? POLLIN
                                                                                      : 0) |
                     (!finished && input.end ? POLLOUT : 0)),
             0}};
        int result = poll(items, 2, 100);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if ((items[0].revents & POLLIN) && fill(terminal, &input) <= 0) {
            reading = 0;
            cancelled = SIGHUP;
        }
        if (items[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            if (!cancelled)
                cancelled = SIGHUP;
            return failed(EIO);
        }
        if ((items[0].revents & POLLOUT) && drain(terminal, &output) < 0)
            return -1;
        if ((items[1].revents & POLLOUT) && drain(master, &input) < 0)
            return -1;
        if (items[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            int result = fill(master, &output);
            if (result < 0)
                return -1;
            if (!result)
                master_open = 0;
        }
    }
}

int account_session_run_stdio(const struct account_profile* profile, int terminal,
                              const char* terminal_type, unsigned terminal_streams,
                              char* const command[], const struct account_session_events* events,
                              int* status) {
    if (!profile || !command || !command[0] || !*command[0] || !status ||
        (events && (!events->begin || !events->end)) || terminal_streams > 7)
        return failed(EINVAL);
    if (geteuid() || getegid())
        return failed(EPERM);
    struct termios original = {0};
    if (tcgetattr(terminal, &original) < 0)
        return -1;
    if (tcgetsid(terminal) != getsid(0) || tcgetpgrp(terminal) != getpgrp())
        return failed(ENOTTY);
    int flags = fcntl(terminal, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDWR)
        return failed(EBADF);
    int error = 0, master = -1, slave = -1, ready[2] = {-1, -1}, go[2] = {-1, -1};
    int quiet = 0, changed_flags = 0, started = 0, reaped = 0;
    pid_t process = -1;
    *status = 0;
    sigset_t blocked, previous_mask;
    sigemptyset(&blocked);
    for (size_t i = 0; i < sizeof(caught) / sizeof(caught[0]); i++)
        sigaddset(&blocked, caught[i]);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous_mask) < 0)
        return -1;
    struct sigaction previous[sizeof(caught) / sizeof(caught[0])];
    struct sigaction action = {.sa_handler = notified};
    sigemptyset(&action.sa_mask);
    cancelled = resized = 0;
    size_t installed = 0;
    for (; installed < sizeof(caught) / sizeof(caught[0]); installed++)
        if (sigaction(caught[installed], &action, &previous[installed]) < 0) {
            error = errno;
            break;
        }
    char path[64] = {0};
    if (!error) {
        master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
        if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 ||
            ptsname_r(master, path, sizeof(path)) != 0)
            error = errno ? errno : EIO;
    }
    if (!error) {
        slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
        struct stat metadata;
        if (slave < 0 || fstat(slave, &metadata) < 0)
            error = errno;
        else if (!S_ISCHR(metadata.st_mode))
            error = ENOTTY;
        else if (fchown(slave, profile->uid, profile->gid) < 0 || fchmod(slave, 0600) < 0 ||
                 tcsetattr(slave, TCSANOW, &original) < 0)
            error = errno;
        struct winsize size;
        if (!error && ioctl(terminal, TIOCGWINSZ, &size) == 0 &&
            ioctl(slave, TIOCSWINSZ, &size) < 0)
            error = errno;
    }
    if (!error && (pipe2(ready, O_CLOEXEC) < 0 || pipe2(go, O_CLOEXEC) < 0))
        error = errno;
    if (!error) {
        process = fork();
        if (!process)
            child(profile, slave, ready[1], go[0], terminal_type, terminal_streams, command);
        if (process < 0)
            error = errno;
    }
    if (slave >= 0)
        close(slave);
    slave = -1;
    if (ready[1] >= 0)
        close(ready[1]);
    ready[1] = -1;
    if (go[0] >= 0)
        close(go[0]);
    go[0] = -1;
    if (sigprocmask(SIG_SETMASK, &previous_mask, NULL) < 0 && !error)
        error = errno;
    if (!error) {
        int setup;
        if (transfer(ready[0], &setup, sizeof(setup), 0) < 0)
            error = errno;
        else if (setup)
            error = setup;
    }
    if (!error) {
        started = 1;
        if (events && events->begin(events->context, process, path) < 0)
            error = errno;
    }
    if (!error) {
        struct termios raw = original;
        cfmakeraw(&raw);
        if (tcsetattr(terminal, TCSANOW, &raw) < 0)
            error = errno;
        else
            quiet = 1;
        if (!error && fcntl(terminal, F_SETFL, flags | O_NONBLOCK) < 0)
            error = errno;
        else if (!error)
            changed_flags = 1;
    }
    if (sigprocmask(SIG_SETMASK, &previous_mask, NULL) < 0 && !error)
        error = errno;
    if (!error) {
        char allowed = 'x';
        if (transfer(go[1], &allowed, 1, 1) < 0)
            error = errno;
    }
    if (go[1] >= 0)
        close(go[1]);
    go[1] = -1;
    if (!error) {
        if (relay(terminal, master, process, status, &reaped) < 0)
            error = errno;
        else
            reaped = 1;
    }
    if (process > 0 && !reaped) {
        signal_child(master, process, SIGKILL);
        while (waitpid(process, status, 0) < 0) {
            if (errno == EINTR)
                continue;
            if (!error)
                error = errno;
            break;
        }
    }
    if (master >= 0)
        close(master);
    for (size_t i = 0; i < 2; i++) {
        if (ready[i] >= 0)
            close(ready[i]);
        if (go[i] >= 0)
            close(go[i]);
    }
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) < 0 && !error)
        error = errno;
    if (changed_flags && fcntl(terminal, F_SETFL, flags) < 0 && !error)
        error = errno;
    if (quiet && tcsetattr(terminal, TCSANOW, &original) < 0 && !error)
        error = errno;
    if (started && events && events->end(events->context, process, *status) < 0 && !error)
        error = errno;
    for (size_t i = installed; i > 0; i--)
        if (sigaction(caught[i - 1], &previous[i - 1], NULL) < 0 && !error)
            error = errno;
    int signal = cancelled;
    cancelled = resized = 0;
    if (sigprocmask(SIG_SETMASK, &previous_mask, NULL) < 0 && !error)
        error = errno;
    if (signal) {
        raise(signal);
        if (!error)
            error = ECANCELED;
    }
    return error ? failed(error) : 0;
}

int account_session_run(const struct account_profile* profile, int terminal,
                        const char* terminal_type, char* const command[],
                        const struct account_session_events* events, int* status) {
    return account_session_run_stdio(profile, terminal, terminal_type, 7, command, events, status);
}
