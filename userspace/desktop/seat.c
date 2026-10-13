// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "seat.h"
#include "authority.h"
#include "../accounts/protected.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef DESKTOP_DIRECTORY
#define DESKTOP_DIRECTORY "/run/axiom64-seat"
#endif

struct desktop_seat {
    int directory, lock;
    pid_t server, clients;
    pid_t owner;
    uid_t uid;
    gid_t gid;
    uint8_t cookie[16];
    int published;
};

static const char* files[] = {"server.auth", "client.auth",  "server.log", "clients.log",
                              "Xorg.log",    "Xorg.log.old", "state"};

static int failed(int error) {
    errno = error;
    return -1;
}

static int display_available(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    int result = connect(fd, (struct sockaddr*)&address, sizeof(address));
    int error = errno;
    close(fd);
    if (!result)
        return failed(EBUSY);
    return error == ENOENT || error == ECONNREFUSED ? 0 : failed(error);
}

static int clear_framebuffer(void) {
    int fd = open("/dev/fb0", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    uint8_t fixed[80] = {0};
    uint32_t variable[40] = {0}, length = 0;
    int error = ioctl(fd, 0x4600, variable) < 0 || ioctl(fd, 0x4602, fixed) < 0 ? errno : 0;
    memcpy(&length, fixed + 24, 4);
    if (!error && (!variable[0] || !variable[1] || variable[6] != 32 || !length ||
                   length > 256u * 1024 * 1024))
        error = EINVAL;
    void* pixels = MAP_FAILED;
    if (!error) {
        pixels = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (pixels == MAP_FAILED)
            error = errno;
        else {
            memset(pixels, 0, length);
            if (munmap(pixels, length) < 0)
                error = errno;
        }
    }
    close(fd);
    return error ? failed(error) : 0;
}

static int state_write(int fd, void* opaque) {
    const struct desktop_seat* seat = opaque;
    return dprintf(fd, "axiom64-seat=1\nowner=%d\nserver=%d\nclients=%d\nuid=%u\n", (int)getpid(),
                   (int)seat->server, (int)seat->clients, (unsigned)seat->uid) < 0
               ? -1
               : 0;
}

static int state_save(struct desktop_seat* seat) {
    seat->published = 1; // Publication can be visible even after a late fsync error.
    int result = account_file_publish(seat->directory, "state", 0600, state_write, seat);
    if (!result)
        seat->published = 1;
    return result;
}

static int remove_files(struct desktop_seat* seat) {
    for (size_t i = 0; i < sizeof(files) / sizeof(*files); i++) {
        struct stat metadata;
        if (fstatat(seat->directory, files[i], &metadata, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno == ENOENT)
                continue;
            return -1;
        }
        if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1 ||
            metadata.st_uid != (!strcmp(files[i], "client.auth") ? seat->uid : 0))
            return failed(EACCES);
    }
    for (size_t i = 0; i < sizeof(files) / sizeof(*files); i++)
        if (unlinkat(seat->directory, files[i], 0) < 0 && errno != ENOENT)
            return -1;
    return fsync(seat->directory);
}

static int recover(struct desktop_seat* seat) {
    // Never clear another server's framebuffer or remove its authorization.
    if (display_available() < 0)
        return -1;
    int fd = account_file_open(seat->directory, "state", O_RDONLY, 0600, 0);
    if (fd < 0)
        return errno == ENOENT ? clear_framebuffer() : -1;
    char bytes[192] = {0};
    ssize_t size = read(fd, bytes, sizeof(bytes) - 1);
    close(fd);
    int owner, server, clients, used = 0;
    unsigned uid;
    if (size <= 0 ||
        sscanf(bytes, "axiom64-seat=1\nowner=%d\nserver=%d\nclients=%d\nuid=%u\n%n", &owner,
               &server, &clients, &uid, &used) != 4 ||
        used != size || owner <= 0 || server < 0 || clients < 0 || uid == UINT32_MAX)
        return failed(EUCLEAN);
    const int pids[] = {owner, server, clients};
    for (size_t i = 0; i < sizeof(pids) / sizeof(*pids); i++)
        if (pids[i] && (kill(pids[i], 0) == 0 || errno != ESRCH))
            return failed(EBUSY);
    seat->uid = uid;
    if (clear_framebuffer() < 0 || remove_files(seat) < 0)
        return -1;
    return 0;
}

int desktop_seat_recover(void) {
    struct desktop_seat seat = {.directory = -1, .lock = -1};
    seat.directory = account_directory_open(DESKTOP_DIRECTORY, 0755, 1);
    if (seat.directory < 0)
        return -1;
    seat.lock = account_file_open(seat.directory, "lock", O_RDWR, 0600, 1);
    int error = seat.lock < 0 || flock(seat.lock, LOCK_EX | LOCK_NB) < 0 ? errno : 0;
    if (!error && recover(&seat) < 0)
        error = errno;
    if (seat.lock >= 0)
        close(seat.lock);
    close(seat.directory);
    return error ? failed(error) : 0;
}

static int private_file(struct desktop_seat* seat, const char* name, int user) {
    int fd =
        openat(seat->directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    int error = fchmod(fd, 0600) < 0 ? errno : 0;
    if (!error && user && (fchown(fd, seat->uid, seat->gid) < 0 || fchmod(fd, 0400) < 0))
        error = errno;
    if (error) {
        close(fd);
        return failed(error);
    }
    return fd;
}

static int close_extra(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3u, UINT32_MAX, 0u) == 0)
        return 0;
    if (errno != ENOSYS && errno != EINVAL)
        return -1;
#endif
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0 || limit.rlim_cur > 1048576)
        return failed(EOVERFLOW);
    for (unsigned fd = 3; fd < limit.rlim_cur; fd++)
        close((int)fd);
    return 0;
}

static void child(const struct account_profile* profile, int output, int server, pid_t parent) {
    int input = open("/dev/null", O_RDONLY);
    if (input < 0 || dup2(input, 0) < 0 || dup2(output, 1) < 0 || dup2(output, 2) < 0 ||
        close_extra() < 0 || setsid() < 0)
        _exit(126);
    for (int number = 1; number < NSIG; number++)
        if (number != SIGKILL && number != SIGSTOP && signal(number, SIG_DFL) == SIG_ERR &&
            errno != EINVAL)
            _exit(126);
    sigset_t mask;
    sigemptyset(&mask);
    if (sigprocmask(SIG_SETMASK, &mask, NULL) < 0)
        _exit(126);
    if (!server && (account_profile_environment(profile, "xterm") < 0 ||
                    account_profile_enter(profile, 0) < 0 || chdir(profile->home) < 0))
        _exit(126);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 || getppid() != parent)
        _exit(126);
    if (server) {
        // Device access stays in this trusted root server. Every X client must
        // present the private session cookie; TCP listening is disabled.
        umask(0);
        execl("/usr/libexec/Xorg", "Xorg", ":0", "-config", "/etc/X11/xorg.conf", "-nolisten",
              "tcp", "-noreset", "-auth", DESKTOP_DIRECTORY "/server.auth", "-retro", "-dumbSched",
              "-extension", "GLX", "-logfile", DESKTOP_DIRECTORY "/Xorg.log", (char*)NULL);
    } else {
        umask(077);
        execl("/bin/busybox", "busybox", "sh", "/etc/desktop-client-session.sh", (char*)NULL);
    }
    _exit(127);
}

static int server_ready(const uint8_t cookie[16]) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct timeval timeout = {1, 0};
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    uint8_t request[48] = {'l', 0, 11, 0, 0, 0, 18, 0, 16, 0, 0, 0};
    memcpy(request + 12, "MIT-MAGIC-COOKIE-1", 18);
    memcpy(request + 32, cookie, 16);
    int result = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
        connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0) {
        size_t sent = 0;
        while (sent < sizeof(request)) {
            ssize_t count = send(fd, request + sent, sizeof(request) - sent, MSG_NOSIGNAL);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
                break;
            sent += (size_t)count;
        }
        uint8_t prefix[8];
        size_t used = 0;
        while (sent == sizeof(request) && used < sizeof(prefix)) {
            ssize_t count = read(fd, prefix + used, sizeof(prefix) - used);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
                break;
            used += (size_t)count;
        }
        result = used == sizeof(prefix) && prefix[0] == 1 && prefix[2] == 11;
    }
    close(fd);
    explicit_bzero(request, sizeof(request));
    return result;
}

static int observe_child(pid_t* pid) {
    if (*pid <= 0)
        return failed(ECHILD);
    int status;
    pid_t result = waitpid(*pid, &status, WNOHANG);
    if (result == *pid) {
        *pid = 0;
        return failed(ECHILD);
    }
    return result < 0 && errno != EINTR ? -1 : 0;
}

int desktop_seat_observe(struct desktop_seat* seat) {
    if (!seat)
        return failed(EINVAL);
    return observe_child(&seat->server) < 0 || observe_child(&seat->clients) < 0 ? -1 : 0;
}

static void stop_child(pid_t child) {
    if (child <= 0)
        return;
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
}

int desktop_seat_stop(struct desktop_seat* seat) {
    if (!seat)
        return 0;
    stop_child(seat->server);
    stop_child(seat->clients);
    int error = clear_framebuffer() < 0 ? errno : 0;
    if (remove_files(seat) < 0 && !error)
        error = errno;
    if (seat->lock >= 0)
        close(seat->lock);
    if (seat->directory >= 0)
        close(seat->directory);
    explicit_bzero(seat, sizeof(*seat));
    free(seat);
    return error ? failed(error) : 0;
}

int desktop_seat_start(const struct account_profile* profile, struct desktop_seat** output) {
    if (!profile || !output || profile->uid == 0 || geteuid() || getegid())
        return failed(EACCES);
    *output = NULL;
    struct desktop_seat* seat = calloc(1, sizeof(*seat));
    if (!seat)
        return -1;
    seat->directory = account_directory_open(DESKTOP_DIRECTORY, 0755, 1);
    seat->owner = getpid();
    seat->lock = -1;
    int error = seat->directory < 0 ? errno : 0;
    if (!error) {
        seat->lock = account_file_open(seat->directory, "lock", O_RDWR, 0600, 1);
        if (seat->lock < 0 || flock(seat->lock, LOCK_EX | LOCK_NB) < 0)
            error = errno;
    }
    if (!error && recover(seat) < 0)
        error = errno;
    seat->uid = profile->uid;
    seat->gid = profile->gid;
    if (!error && (account_nonce(seat->cookie) < 0 || state_save(seat) < 0))
        error = errno;
    for (unsigned user = 0; !error && user < 2; user++) {
        int fd = private_file(seat, user ? "client.auth" : "server.auth", user);
        if (fd < 0)
            error = errno;
        else {
            if (desktop_authority_write(fd, 0, seat->cookie) < 0 || fsync(fd) < 0)
                error = errno;
            close(fd);
        }
    }
    int server_log = -1, client_log = -1;
    if (!error) {
        server_log = private_file(seat, "server.log", 0);
        client_log = private_file(seat, "clients.log", 0);
        if (server_log < 0 || client_log < 0)
            error = errno;
    }
    if (!error) {
        seat->server = fork();
        if (!seat->server)
            child(profile, server_log, 1, seat->owner);
        if (seat->server < 0 || state_save(seat) < 0)
            error = errno;
    }
    unsigned attempt = 0;
    for (; !error && attempt < 100; attempt++) {
        if (observe_child(&seat->server) < 0) {
            error = errno;
            break;
        }
        if (server_ready(seat->cookie) == 1)
            break;
        struct timespec delay = {0, 100000000};
        nanosleep(&delay, NULL);
    }
    if (!error && attempt == 100)
        error = ETIMEDOUT;
    if (!error) {
        seat->clients = fork();
        if (!seat->clients)
            child(profile, client_log, 0, seat->owner);
        if (seat->clients < 0 || state_save(seat) < 0)
            error = errno;
    }
    if (server_log >= 0)
        close(server_log);
    if (client_log >= 0)
        close(client_log);
    if (error) {
        if (seat->published) {
            int diagnostic = account_file_open(seat->directory, "server.log", O_RDONLY, 0600, 0);
            if (diagnostic >= 0) {
                char bytes[8192];
                ssize_t size = read(diagnostic, bytes, sizeof(bytes));
                if (size > 0) {
                    ssize_t written = write(2, bytes, (size_t)size);
                    (void)written;
                }
                close(diagnostic);
            }
            desktop_seat_stop(seat);
        } else {
            if (seat->lock >= 0)
                close(seat->lock);
            if (seat->directory >= 0)
                close(seat->directory);
            explicit_bzero(seat, sizeof(*seat));
            free(seat);
        }
        return failed(error);
    }
    dprintf(1, "\nACCOUNT_DESKTOP_READY uid=%u server=%d clients=%d\n", (unsigned)profile->uid,
            (int)seat->server, (int)seat->clients);
    *output = seat;
    return 0;
}
