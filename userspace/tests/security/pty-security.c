// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "PTY_SECURITY_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno, \
                    #expression);                                                                  \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static volatile sig_atomic_t terminal_signals;

static void observe(const char* name) {
    printf("PTY_SECURITY_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void signal_handler(int number) {
    terminal_signals |= number == SIGHUP ? 1 : 2;
}

static void drop(uid_t uid) {
    CHECK(setgroups(0, NULL) == 0);
    CHECK(setresgid(uid, uid, uid) == 0);
    CHECK(setresuid(uid, uid, uid) == 0);
}

static void reap(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void send_byte(int fd) {
    CHECK(write(fd, "x", 1) == 1);
}

static void receive_byte(int fd) {
    char byte;
    ssize_t size;
    do {
        size = read(fd, &byte, 1);
    } while (size < 0 && errno == EINTR);
    CHECK(size == 1 && byte == 'x');
}

static int master(char path[64]) {
    memset(path, 0, 64);
    int fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(fd >= 0);
    CHECK(ptsname_r(fd, path, 64) == 0);
    return fd;
}

static void ordinary_owner(void) {
    int ready[2], finish[2];
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    pid_t owner = fork();
    CHECK(owner >= 0);
    if (!owner) {
        close(ready[0]);
        close(finish[1]);
        drop(1001);
        char path[64];
        int fd = master(path);
        struct stat metadata;
        CHECK(stat(path, &metadata) == 0);
        CHECK(S_ISCHR(metadata.st_mode) && (metadata.st_mode & 0777) == 0600);
        CHECK(metadata.st_uid == 1001 && metadata.st_gid == 1001);
        CHECK(grantpt(fd) == 0 && unlockpt(fd) == 0);
        int slave = open(path, O_RDWR | O_NOCTTY);
        CHECK(slave >= 0);
        CHECK(write(ready[1], path, sizeof(path)) == sizeof(path));
        receive_byte(finish[0]);
        close(slave);
        close(fd);
        _exit(0);
    }
    close(ready[1]);
    close(finish[0]);
    char path[64];
    CHECK(read(ready[0], path, sizeof(path)) == sizeof(path));
    pid_t other = fork();
    CHECK(other >= 0);
    if (!other) {
        drop(1002);
        CHECK(open(path, O_RDWR | O_NOCTTY) == -1 && errno == EACCES);
        CHECK(chmod(path, 0666) == -1 && errno == EPERM);
        _exit(0);
    }
    reap(other);
    int root = open(path, O_RDWR | O_NOCTTY);
    CHECK(root >= 0);
    close(root);
    send_byte(finish[1]);
    reap(owner);
    struct stat metadata;
    CHECK(stat(path, &metadata) == -1 && errno == ENOENT);
    close(ready[0]);
    close(finish[1]);
    observe("ordinary_creator_private_owner_foreign_denial_root_access");
}

static void takeover_and_hangup(void) {
    char path[64];
    int fd = master(path);
    CHECK(grantpt(fd) == 0 && unlockpt(fd) == 0);
    int slave = open(path, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0 && fchown(slave, 1001, 1001) == 0);
    int ready[2], finish[2];
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    pid_t owner = fork();
    CHECK(owner >= 0);
    if (!owner) {
        close(fd);
        close(ready[0]);
        close(finish[1]);
        CHECK(setsid() == getpid());
        drop(1001);
        struct sigaction action = {.sa_handler = signal_handler, .sa_flags = SA_RESTART};
        CHECK(sigaction(SIGHUP, &action, NULL) == 0);
        CHECK(sigaction(SIGCONT, &action, NULL) == 0);
        CHECK(ioctl(slave, TIOCSCTTY, 0) == 0);
        CHECK(tcgetsid(slave) == getpid() && tcgetpgrp(slave) == getpgrp());
        CHECK(tcsetpgrp(slave, getpgrp()) == 0);
        int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
        CHECK(tty >= 0 && tcgetsid(tty) == getpid());
        close(tty);
        pid_t thief = fork();
        CHECK(thief >= 0);
        if (!thief) {
            CHECK(ioctl(slave, TIOCSCTTY, 0) == -1 && errno == EPERM);
            CHECK(setsid() == getpid());
            CHECK(ioctl(slave, TIOCSCTTY, 0) == -1 && errno == EPERM);
            CHECK(ioctl(slave, TIOCSCTTY, 1) == -1 && errno == EPERM);
            CHECK(ioctl(slave, TIOCSCTTY, 2) == -1 && errno == EPERM);
            CHECK(tcsetpgrp(slave, getpgrp()) == -1 && errno == ENOTTY);
            CHECK(tcgetpgrp(slave) == -1 && errno == ENOTTY);
            CHECK(tcgetsid(slave) == -1 && errno == ENOTTY);
            CHECK(ioctl(slave, TIOCNOTTY) == -1 && errno == ENOTTY);
            _exit(0);
        }
        reap(thief);
        send_byte(ready[1]);
        receive_byte(finish[0]);
        CHECK(terminal_signals == 3);
        CHECK(open("/dev/tty", O_RDWR | O_NOCTTY) == -1 && errno == ENXIO);
        char byte;
        CHECK(read(slave, &byte, 1) == 0);
        CHECK(write(slave, "x", 1) == -1 && errno == EIO);
        close(slave);
        _exit(0);
    }
    close(ready[1]);
    close(finish[0]);
    receive_byte(ready[0]);
    CHECK(tcgetsid(fd) == owner && tcgetpgrp(fd) == owner);
    observe("owned_session_foreground_and_unprivileged_takeover_denial");
    struct stat before, after;
    CHECK(fstat(slave, &before) == 0);
    int duplicate = dup(fd);
    CHECK(duplicate >= 0);
    close(fd);
    CHECK(stat(path, &after) == 0);
    close(duplicate);
    CHECK(stat(path, &after) == -1 && errno == ENOENT);
    CHECK(fstat(slave, &after) == 0 && before.st_ino == after.st_ino);
    CHECK(after.st_nlink == 0 && after.st_uid == 1001 && (after.st_mode & 0777) == 0600);
    char next_path[64];
    int next = master(next_path);
    CHECK(strcmp(next_path, path) != 0);
    struct stat next_metadata;
    CHECK(stat(next_path, &next_metadata) == 0 && next_metadata.st_uid == 0);
    CHECK(next_metadata.st_ino != after.st_ino && (next_metadata.st_mode & 0777) == 0600);
    close(next);
    send_byte(finish[1]);
    reap(owner);
    close(slave);
    close(ready[0]);
    close(finish[1]);
    observe("last_master_unlinks_hangs_up_retained_slave_identity");
}

static void privileged_takeover(void) {
    char path[64];
    int fd = master(path);
    CHECK(unlockpt(fd) == 0);
    int slave = open(path, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0);
    int ready[2], finish[2];
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    pid_t owner = fork();
    CHECK(owner >= 0);
    if (!owner) {
        close(fd);
        close(ready[0]);
        close(finish[1]);
        CHECK(setsid() == getpid());
        drop(1001);
        CHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR);
        CHECK(ioctl(slave, TIOCSCTTY, 0) == 0);
        send_byte(ready[1]);
        receive_byte(finish[0]);
        CHECK(open("/dev/tty", O_RDWR | O_NOCTTY) == -1 && errno == ENXIO);
        _exit(0);
    }
    close(ready[1]);
    close(finish[0]);
    receive_byte(ready[0]);
    pid_t administrator = fork();
    CHECK(administrator >= 0);
    if (!administrator) {
        close(fd);
        CHECK(setsid() == getpid());
        CHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR);
        CHECK(ioctl(slave, TIOCSCTTY, 0) == -1 && errno == EPERM);
        CHECK(ioctl(slave, TIOCSCTTY, 2) == -1 && errno == EPERM);
        CHECK(ioctl(slave, TIOCSCTTY, 1) == 0);
        CHECK(tcgetsid(slave) == getpid());
        CHECK(ioctl(slave, TIOCNOTTY) == 0);
        _exit(0);
    }
    reap(administrator);
    send_byte(finish[1]);
    reap(owner);
    close(fd);
    close(slave);
    close(ready[0]);
    close(finish[1]);
    observe("explicit_privileged_takeover_and_session_detach");
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "guest")));
    CHECK(getuid() == 0 && geteuid() == 0 && getegid() == 0);
    if (argc == 2) {
        const char* devices[] = {"/dev/console",      "/dev/ttyS0",        "/dev/tty0", "/dev/tty1",
                                 "/dev/input/event0", "/dev/input/event1", "/dev/fb0"};
        for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
            struct stat value;
            CHECK(stat(devices[i], &value) == 0 && S_ISCHR(value.st_mode));
            CHECK(!value.st_uid && !value.st_gid && (value.st_mode & 0777) == 0600);
            int device = open(devices[i], O_RDWR | O_NOCTTY);
            CHECK(device >= 0);
            close(device);
        }
        pid_t ordinary = fork();
        CHECK(ordinary >= 0);
        if (!ordinary) {
            drop(1002);
            for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
                CHECK(open(devices[i], O_RDWR | O_NOCTTY) == -1 && errno == EACCES);
                CHECK(chmod(devices[i], 0666) == -1 && errno == EPERM);
            }
            _exit(0);
        }
        reap(ordinary);
        observe("seven_raw_console_input_display_devices_root_private");
    }
    int null = open("/dev/null", O_RDWR | O_NOCTTY);
    CHECK(null >= 0);
    struct termios nonterminal;
    CHECK(tcgetattr(null, &nonterminal) == -1 && errno == ENOTTY);
    close(null);
    observe("nonterminal_character_device_rejects_terminal_operations");
    char path[64];
    int fd = master(path), locked = -1;
    struct stat metadata;
    CHECK(stat(path, &metadata) == 0);
    CHECK(S_ISCHR(metadata.st_mode) && (metadata.st_mode & 0777) == 0600);
    CHECK(metadata.st_uid == 0 && metadata.st_gid == 0);
    CHECK(tcgetsid(fd) == -1 && errno == ENOTTY);
    CHECK(ioctl(fd, TIOCGPTLCK, &locked) == 0 && locked == 1);
    CHECK(open(path, O_RDWR | O_NOCTTY) == -1 && errno == EIO);
    observe("private_metadata_initial_lock_and_exact_open_errno");
    CHECK(grantpt(fd) == 0 && unlockpt(fd) == 0);
    CHECK(ioctl(fd, TIOCGPTLCK, &locked) == 0 && locked == 0);
    CHECK(syscall(SYS_ioctl, fd, (unsigned long)TIOCSPTLCK, (void*)1) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_ioctl, fd, (unsigned long)TIOCGPTLCK, (void*)1) == -1 && errno == EFAULT);
    int slave = open(path, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0);
    CHECK(tcgetpgrp(slave) == -1 && errno == ENOTTY);
    CHECK(tcgetsid(slave) == -1 && errno == ENOTTY);
    CHECK(ioctl(slave, TIOCNOTTY) == -1 && errno == ENOTTY);
    locked = -7;
    CHECK(ioctl(fd, TIOCSPTLCK, &locked) == 0);
    CHECK(ioctl(fd, TIOCGPTLCK, &locked) == 0 && locked == 1);
    CHECK(open(path, O_RDWR | O_NOCTTY) == -1 && errno == EIO);
    observe("lock_relock_invalid_addresses_and_unattached_session_denial");
    struct termios term;
    CHECK(tcgetattr(slave, &term) == 0);
    cfmakeraw(&term);
    CHECK(tcsetattr(slave, TCSANOW, &term) == 0);
    CHECK(write(fd, "input", 5) == 5);
    char bytes[8];
    CHECK(read(slave, bytes, 5) == -1 && errno == EIO);
    CHECK(write(slave, "x", 1) == -1 && errno == EIO);
    CHECK(unlockpt(fd) == 0);
    int reopened = open(path, O_RDWR | O_NOCTTY);
    CHECK(reopened >= 0);
    CHECK(read(slave, bytes, 5) == 5 && memcmp(bytes, "input", 5) == 0);
    CHECK(write(slave, "output", 6) == 6);
    CHECK(read(fd, bytes, 6) == 6 && memcmp(bytes, "output", 6) == 0);
    close(reopened);
    close(slave);
    close(fd);
    observe("failed_locked_open_io_error_successful_reopen_restores_raw_io");
    ordinary_owner();
    takeover_and_hangup();
    privileged_takeover();
    struct statvfs before, after;
    CHECK(statvfs("/dev/pts", &before) == 0);
    for (unsigned i = 0; i < 512; i++) {
        fd = master(path);
        CHECK(stat(path, &metadata) == 0 && metadata.st_uid == 0);
        CHECK((metadata.st_mode & 0777) == 0600);
        CHECK(ioctl(fd, TIOCGPTLCK, &locked) == 0 && locked == 1);
        close(fd);
        CHECK(stat(path, &metadata) == -1 && errno == ENOENT);
    }
    CHECK(statvfs("/dev/pts", &after) == 0);
    CHECK(after.f_ffree == before.f_ffree);
    observe("512_fresh_private_locked_pairs_without_inode_leak");
    printf("PTY_SECURITY_PASS observations=%u recycled_pairs=512\n", observations);
    return 0;
}
