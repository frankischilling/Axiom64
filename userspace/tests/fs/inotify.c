// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static void check(int condition, const char* detail) {
    if (!condition) {
        fprintf(stderr, "INOTIFY_FAIL %s errno=%d (%s)\n", detail, errno, strerror(errno));
        exit(1);
    }
}

static void path(char* buffer, size_t size, const char* directory, const char* name) {
    int length = snprintf(buffer, size, "%s/%s", directory, name);
    check(length > 0 && (size_t)length < size, "fixture path");
}

static int watch(int fd, const char* name, uint32_t mask) {
    int wd = inotify_add_watch(fd, name, mask);
    check(wd > 0, "add watch");
    return wd;
}

static void empty(int fd) {
    unsigned char buffer[512];
    check(read(fd, buffer, sizeof(buffer)) == -1 && errno == EAGAIN, "empty queue");
}

static uint32_t event(unsigned char** next, const unsigned char* end, int wd, uint32_t mask,
                      const char* name) {
    struct inotify_event record;
    check((size_t)(end - *next) >= sizeof(record), "complete header");
    memcpy(&record, *next, sizeof(record));
    *next += sizeof(record);
    size_t length = strlen(name);
    size_t padded = length ? (length + 16) & ~(size_t)15 : 0;
    if (record.wd != wd || record.mask != mask || record.len != padded)
        fprintf(stderr, "expected wd=%d mask=%x len=%zu, got wd=%d mask=%x len=%u\n", wd, mask,
                padded, record.wd, record.mask, record.len);
    check(record.wd == wd && record.mask == mask && record.len == padded &&
              (size_t)(end - *next) >= padded,
          "watch, mask and complete name length");
    check(memcmp(*next, name, length) == 0, "event name");
    for (size_t index = length; index < padded; ++index)
        check((*next)[index] == 0, "zero name padding");
    *next += padded;
    return record.cookie;
}

static void make_file(const char* name) {
    int file = open(name, O_CREAT | O_EXCL | O_WRONLY, 0600);
    check(file >= 0 && close(file) == 0, "create fixture file");
}

static void descriptor(int legacy_seek) {
    check(inotify_init1(1) == -1 && errno == EINVAL, "reject invalid init flags");
    int fd = inotify_init();
    check(fd >= 0 && !(fcntl(fd, F_GETFD) & FD_CLOEXEC) && !(fcntl(fd, F_GETFL) & O_NONBLOCK),
          "legacy init flags");
    check(close(fd) == 0, "close legacy instance");
    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    check(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC) && (fcntl(fd, F_GETFL) & O_NONBLOCK),
          "init flags");
    struct stat info;
    check(fstat(fd, &info) == 0 && info.st_mode == 0600 && info.st_nlink == 1, "descriptor stat");
    off_t seek = lseek(fd, 91, SEEK_SET);
    check(legacy_seek ? seek == -1 && errno == ESPIPE : seek == 0, "descriptor seek");
    unsigned char buffer[16];
    check(read(fd, buffer, 0) == -1 && errno == EAGAIN, "empty scalar read");
    check(pread(fd, buffer, sizeof(buffer), 0) == -1 && errno == ESPIPE, "positioned read");
    check(write(fd, buffer, 0) == -1 && errno == EBADF, "readonly description");
    int count = -1;
    check(ioctl(fd, FIONREAD, &count) == 0 && !count, "empty byte inventory");
    check(inotify_rm_watch(fd, 1) == -1 && errno == EINVAL, "unknown watch");
    check(close(fd) == 0, "close descriptor");
    puts("INOTIFY_CASE descriptor");
}

static void replacement(const char* directory, int is_directory) {
    char source[512], target[512];
    path(source, sizeof(source), directory, "source");
    path(target, sizeof(target), directory, "target");
    if (is_directory)
        check(mkdir(source, 0700) == 0 && mkdir(target, 0700) == 0, "make directory replacement");
    else {
        make_file(source);
        make_file(target);
    }
    int fd = inotify_init1(IN_NONBLOCK);
    check(fd >= 0, "replacement instance");
    int parent = watch(fd, directory, IN_ALL_EVENTS);
    int original = watch(fd, source, IN_ALL_EVENTS);
    int replaced = watch(fd, target, IN_ALL_EVENTS);
    check(rename(source, target) == 0, "replace watched target");
    unsigned char buffer[256], *next = buffer;
    check(read(fd, buffer, sizeof(buffer)) == 128, "replacement event bytes");
    const unsigned char* end = buffer + 128;
    uint32_t type = is_directory ? IN_ISDIR : 0;
    uint32_t from = event(&next, end, parent, IN_MOVED_FROM | type, "source");
    uint32_t to = event(&next, end, parent, IN_MOVED_TO | type, "target");
    check(from && from == to, "replacement rename cookie");
    event(&next, end, replaced, IN_ATTRIB | type, "");
    event(&next, end, original, IN_MOVE_SELF, "");
    event(&next, end, replaced, IN_DELETE_SELF, "");
    event(&next, end, replaced, IN_IGNORED, "");
    check(next == end, "complete replacement event order");
    check(close(fd) == 0 && (is_directory ? rmdir(target) : unlink(target)) == 0,
          "close replacement fixture");
}

static void namespace_events(const char* directory) {
    char old[512], new[512], alias[512], symbol[512];
    path(old, sizeof(old), directory, "old");
    path(new, sizeof(new), directory, "renamed");
    path(alias, sizeof(alias), directory, "alias");
    path(symbol, sizeof(symbol), directory, "symbol");
    int fd = inotify_init1(IN_NONBLOCK);
    check(fd >= 0, "namespace instance");
    int parent = watch(fd, directory, IN_ALL_EVENTS | IN_ONLYDIR);
    int file = open(old, O_CREAT | O_EXCL | O_RDWR, 0600);
    check(file >= 0, "create watched child");
    int wd = watch(fd, old, IN_ALL_EVENTS);
    check(watch(fd, old, IN_MASK_ADD | IN_MODIFY) == wd, "update watch in place");
    check(inotify_add_watch(fd, old, IN_MASK_CREATE | IN_MODIFY) == -1 && errno == EEXIST,
          "exclusive watch insertion");
    check(inotify_add_watch(fd, old, IN_ONLYDIR | IN_MODIFY) == -1 && errno == ENOTDIR,
          "directory-only watch");
    check(inotify_add_watch(file, old, IN_MODIFY) == -1 && errno == EINVAL, "wrong descriptor");
    int path_only = open(old, O_PATH);
    check(path_only >= 0 && inotify_add_watch(path_only, old, IN_MODIFY) == -1 && errno == EBADF &&
              inotify_rm_watch(path_only, wd) == -1 && errno == EBADF && close(path_only) == 0,
          "path descriptor cannot control watches");
    check(rename(old, new) == 0 && write(file, "A", 1) == 1 && unlink(new) == 0 &&
              write(file, "B", 1) == 1 && close(file) == 0,
          "retained write and close after unlink");
    unsigned char buffer[512], *next = buffer;
    int count;
    check(ioctl(fd, FIONREAD, &count) == 0 && count == 368, "record byte inventory");
    check(read(fd, buffer, 16) == -1 && errno == EINVAL, "short scalar read");
    struct iovec vectors[] = {{buffer, 16}, {buffer + 16, sizeof(buffer) - 16}};
    check(readv(fd, vectors, 2) == -1 && errno == EINVAL, "events cannot split across vectors");
    check(read(fd, buffer, sizeof(buffer)) == count, "read complete namespace trace");
    const unsigned char* end = buffer + count;
    event(&next, end, parent, IN_CREATE, "old");
    event(&next, end, parent, IN_OPEN, "old");
    uint32_t from = event(&next, end, parent, IN_MOVED_FROM, "old");
    uint32_t to = event(&next, end, parent, IN_MOVED_TO, "renamed");
    check(from && from == to, "shared nonzero rename cookie");
    event(&next, end, wd, IN_MOVE_SELF, "");
    event(&next, end, parent, IN_MODIFY, "renamed");
    event(&next, end, wd, IN_MODIFY, "");
    event(&next, end, wd, IN_ATTRIB, "");
    event(&next, end, parent, IN_DELETE, "renamed");
    event(&next, end, parent, IN_MODIFY, "renamed");
    event(&next, end, wd, IN_MODIFY, "");
    event(&next, end, parent, IN_CLOSE_WRITE, "renamed");
    event(&next, end, wd, IN_CLOSE_WRITE, "");
    event(&next, end, wd, IN_DELETE_SELF, "");
    event(&next, end, wd, IN_IGNORED, "");
    check(next == end, "exact namespace event order");
    empty(fd);
    check(close(fd) == 0, "close namespace watch");

    make_file(old);
    check(link(old, alias) == 0 && symlink(old, symbol) == 0, "aliases");
    fd = inotify_init1(IN_NONBLOCK);
    check(fd >= 0, "alias instance");
    wd = watch(fd, old, IN_ATTRIB);
    check(watch(fd, alias, IN_MASK_ADD | IN_MODIFY) == wd &&
              watch(fd, symbol, IN_MASK_ADD | IN_OPEN) == wd,
          "same inode through hardlink and followed symlink");
    int symlink_wd = watch(fd, symbol, IN_DONT_FOLLOW | IN_DELETE_SELF);
    check(symlink_wd != wd, "watch symlink inode itself");
    check(unlink(symbol) == 0 && unlink(old) == 0, "unlink aliases");
    next = buffer;
    check(read(fd, buffer, sizeof(buffer)) == 48, "symlink retirement and hardlink count event");
    end = buffer + 48;
    event(&next, end, symlink_wd, IN_DELETE_SELF, "");
    event(&next, end, symlink_wd, IN_IGNORED, "");
    event(&next, end, wd, IN_ATTRIB, "");
    check(inotify_rm_watch(fd, wd) == 0 && inotify_rm_watch(fd, wd) == -1 && errno == EINVAL,
          "remove inode watch");
    next = buffer;
    check(read(fd, buffer, sizeof(buffer)) == 16, "explicit watch removal event");
    event(&next, buffer + 16, wd, IN_IGNORED, "");
    check(unlink(alias) == 0 && close(fd) == 0, "close alias fixture");
    if (getuid()) {
        fd = inotify_init1(IN_NONBLOCK);
        check(fd >= 0, "permission instance");
        make_file(old);
        check(chmod(old, 0200) == 0 && inotify_add_watch(fd, old, IN_MODIFY) == -1 &&
                  errno == EACCES,
              "watch requires inode read permission");
        check(unlink(old) == 0 && close(fd) == 0, "close permission fixture");
    }
    replacement(directory, 0);
    replacement(directory, 1);
    puts("INOTIFY_CASE namespace");
}

static void readiness(const char* directory) {
    char first[512], second[512], third[512];
    path(first, sizeof(first), directory, "first");
    path(second, sizeof(second), directory, "second");
    path(third, sizeof(third), directory, "third");
    int fd = inotify_init1(IN_NONBLOCK), epoll = epoll_create1(EPOLL_CLOEXEC);
    check(fd >= 0 && epoll >= 0, "readiness descriptors");
    int wd = watch(fd, directory, IN_CREATE);
    struct epoll_event interest = {.events = EPOLLIN | EPOLLET, .data.u64 = 71}, received;
    check(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &interest) == 0, "register edge interest");
    check(epoll_wait(epoll, &received, 1, 0) == 0, "empty edge");
    make_file(first);
    check(epoll_wait(epoll, &received, 1, 0) == 1 && received.events == EPOLLIN &&
              received.data.u64 == 71,
          "first edge");
    make_file(second);
    check(epoll_wait(epoll, &received, 1, 0) == 1 && received.events == EPOLLIN,
          "new event wakes a ready edge watch");
    struct pollfd pollfd = {.fd = fd, .events = POLLIN | POLLOUT};
    check(poll(&pollfd, 1, 0) == 1 && pollfd.revents == POLLIN, "read-only poll mask");
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    struct timeval timeout = {0};
    check(select(fd + 1, &readfds, NULL, NULL, &timeout) == 1 && FD_ISSET(fd, &readfds),
          "select readable");
    unsigned char buffer[128], *next = buffer;
    struct iovec vectors[] = {{buffer, 32}, {buffer + 32, 32}};
    int duplicate = dup(fd);
    check(duplicate >= 0 && close(fd) == 0, "retain instance through duplicate");
    check(readv(duplicate, vectors, 2) == 64, "two whole vector records");
    event(&next, buffer + 64, wd, IN_CREATE, "first");
    event(&next, buffer + 64, wd, IN_CREATE, "second");

    check(watch(duplicate, directory, IN_CREATE | IN_ONESHOT) == wd, "replace mask with one-shot");
    make_file(third);
    next = buffer;
    check(read(duplicate, buffer, sizeof(buffer)) == 48, "one-shot retirement");
    event(&next, buffer + 48, wd, IN_CREATE, "third");
    event(&next, buffer + 48, wd, IN_IGNORED, "");
    empty(duplicate);
    check(close(duplicate) == 0 && close(epoll) == 0 && unlink(first) == 0 && unlink(second) == 0 &&
              unlink(third) == 0,
          "close readiness fixture");
    puts("INOTIFY_CASE readiness");
}

static void excluded_and_copy_fault(const char* directory) {
    char old[512], file_name[512];
    path(old, sizeof(old), directory, "detached");
    path(file_name, sizeof(file_name), directory, "copy-fault");
    int fd = inotify_init1(IN_NONBLOCK);
    check(fd >= 0, "excluded unlink instance");
    int file = open(old, O_CREAT | O_EXCL | O_RDWR, 0600);
    check(file >= 0, "open detached fixture");
    int parent = watch(fd, directory, IN_ALL_EVENTS | IN_EXCL_UNLINK);
    int wd = watch(fd, old, IN_ALL_EVENTS | IN_EXCL_UNLINK);
    check(unlink(old) == 0 && write(file, "x", 1) == 1 && close(file) == 0, "write after unlink");
    unsigned char buffer[256], *next = buffer;
    check(read(fd, buffer, sizeof(buffer)) == 80, "excluded detached event inventory");
    event(&next, buffer + 80, wd, IN_ATTRIB, "");
    event(&next, buffer + 80, parent, IN_DELETE, "detached");
    event(&next, buffer + 80, wd, IN_DELETE_SELF, "");
    event(&next, buffer + 80, wd, IN_IGNORED, "");
    empty(fd);

    watch(fd, directory, IN_CREATE);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char* mapping =
        mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(mapping != MAP_FAILED && mprotect(mapping + page, page, PROT_NONE) == 0,
          "protected copy boundary");
    make_file(file_name);
    check(read(fd, mapping + page - 16, 32) == -1 && errno == EFAULT, "late record copy fault");
    struct inotify_event copied;
    memcpy(&copied, mapping + page - 16, sizeof(copied));
    check(copied.wd == parent && copied.mask == IN_CREATE && copied.len == 16,
          "completed header before name copy fault");
    empty(fd);
    check(munmap(mapping, page * 2) == 0 && close(fd) == 0 && unlink(file_name) == 0,
          "close copy fault fixture");
    puts("INOTIFY_CASE detachment");
}

static void attributes(const char* directory) {
    char name[512];
    path(name, sizeof(name), directory, "metadata");
    int file = open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    int fd = inotify_init1(IN_NONBLOCK);
    check(file >= 0 && fd >= 0, "metadata fixture");
    const uint32_t mask = IN_ATTRIB | IN_MODIFY | IN_ACCESS;
    int parent = watch(fd, directory, mask);
    int wd = watch(fd, name, mask);
    check(fchmod(file, 0640) == 0 && ftruncate(file, 3) == 0, "mutate file metadata and size");
    unsigned char value[3], buffer[512], *next = buffer;
    check(pread(file, value, sizeof(value), 0) == sizeof(value), "read observed inode");
    check(setxattr(name, "user.notify", "a", 1, 0) == 0 && removexattr(name, "user.notify") == 0,
          "change file attributes");
    struct timespec times[] = {{1000000000, 0}, {0, UTIME_OMIT}};
    check(utimensat(AT_FDCWD, name, times, 0) == 0, "set only access time");
    times[0].tv_nsec = UTIME_OMIT;
    times[1] = (struct timespec){1000000010, 0};
    check(utimensat(AT_FDCWD, name, times, 0) == 0, "set only modification time");
    times[0] = (struct timespec){1000000020, 0};
    check(utimensat(AT_FDCWD, name, times, 0) == 0, "set both times");
    const uint32_t expected[] = {IN_ATTRIB, IN_MODIFY, IN_ACCESS, IN_ATTRIB,
                                 IN_ATTRIB, IN_ACCESS, IN_MODIFY, IN_ATTRIB};
    size_t total = 48 * (sizeof(expected) / sizeof(expected[0]));
    check(read(fd, buffer, sizeof(buffer)) == (ssize_t)total, "metadata event bytes");
    const unsigned char* end = buffer + total;
    for (size_t index = 0; index < sizeof(expected) / sizeof(expected[0]); ++index) {
        event(&next, end, parent, expected[index], "metadata");
        event(&next, end, wd, expected[index], "");
    }
    check(next == end, "exact metadata effects");
    check(close(fd) == 0 && close(file) == 0 && unlink(name) == 0, "close metadata fixture");
    puts("INOTIFY_CASE attributes");
}

static int exec_reader(int closed, int retained) {
    check(fcntl(closed, F_GETFD) == -1 && errno == EBADF, "exec closes only tagged descriptor");
    unsigned char buffer[32], *next = buffer;
    check(read(retained, buffer, sizeof(buffer)) == sizeof(buffer), "exec inherits pending event");
    int32_t wd;
    memcpy(&wd, buffer, sizeof(wd));
    check(wd > 0, "retained watch ID");
    event(&next, buffer + sizeof(buffer), wd, IN_CREATE, "notification");
    return 0;
}

static void exec_lifetime(const char* executable, const char* directory, const char* name) {
    int tagged = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    check(tagged >= 0, "exec instance");
    watch(tagged, directory, IN_CREATE);
    int retained = dup(tagged);
    check(retained >= 0, "exec alias");
    make_file(name);
    pid_t child = fork();
    check(child >= 0, "fork exec reader");
    if (!child) {
        char fd0[24], fd1[24];
        snprintf(fd0, sizeof(fd0), "%d", tagged);
        snprintf(fd1, sizeof(fd1), "%d", retained);
        char* const args[] = {(char*)executable, "--exec-reader", fd0, fd1, NULL};
        execv(executable, args);
        check(0, "exec reader");
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "exec child result");
    empty(tagged);
    check(close(retained) == 0 && close(tagged) == 0 && unlink(name) == 0, "close exec fixture");
}

static volatile sig_atomic_t interrupted;

static void signal_handler(int signal) {
    interrupted = signal;
}

static void wait_and_lifetime(const char* executable, const char* directory) {
    char entry[512], cwd[512];
    path(entry, sizeof(entry), directory, "notification");
    path(cwd, sizeof(cwd), directory, "removed-cwd");
    int fd = inotify_init(), connection[2];
    check(fd >= 0 && pipe(connection) == 0, "blocking fixture");
    int wd = watch(fd, directory, IN_CREATE);
    pid_t child = fork();
    check(child >= 0, "fork blocking reader");
    if (!child) {
        unsigned char buffer[128], *next = buffer;
        close(connection[0]);
        check(write(connection[1], "r", 1) == 1, "reader enters wait");
        check(read(fd, buffer, sizeof(buffer)) == 32, "wake blocked reader across fork");
        event(&next, buffer + 32, wd, IN_CREATE, "notification");
        check(write(connection[1], "d", 1) == 1, "reader completed");
        _exit(0);
    }
    close(connection[1]);
    char state;
    check(read(connection[0], &state, 1) == 1 && state == 'r', "reader synchronized");
    struct pollfd done = {.fd = connection[0], .events = POLLIN};
    check(poll(&done, 1, 35) == 0, "reader stays blocked before event");
    make_file(entry);
    check(poll(&done, 1, 2000) == 1 && read(connection[0], &state, 1) == 1 && state == 'd',
          "reader resumes");
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "reader child result");
    check(close(connection[0]) == 0 && unlink(entry) == 0, "retire child fixture");

    struct sigaction action = {.sa_handler = signal_handler};
    check(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGALRM, &action, NULL) == 0,
          "install interrupt handler");
    unsigned char buffer[128], *next = buffer;
    alarm(1);
    check(read(fd, buffer, sizeof(buffer)) == -1 && errno == EINTR && interrupted == SIGALRM,
          "signal cancels blocked descriptor read");
    check(close(fd) == 0, "close blocking instance");
    exec_lifetime(executable, directory, entry);

    int previous = open("/", O_RDONLY | O_DIRECTORY);
    fd = inotify_init1(IN_NONBLOCK);
    check(previous >= 0 && fd >= 0 && mkdir(cwd, 0700) == 0, "directory retirement fixture");
    wd = watch(fd, cwd, IN_DELETE_SELF);
    check(chdir(cwd) == 0 && rmdir(cwd) == 0, "remove current directory");
    empty(fd);
    check(fchdir(previous) == 0 && close(previous) == 0, "release current directory");
    check(read(fd, buffer, sizeof(buffer)) == 32, "directory retirement after last reference");
    event(&next, buffer + 32, wd, IN_DELETE_SELF, "");
    event(&next, buffer + 32, wd, IN_IGNORED, "");
    check(close(fd) == 0, "close directory retirement watch");
    puts("INOTIFY_CASE lifetime");
}

static void unmount_event(const char* mountpoint) {
    int fd = inotify_init1(IN_NONBLOCK);
    check(fd >= 0, "unmount instance");
    int wd = watch(fd, mountpoint, IN_ATTRIB);
    check(umount(mountpoint) == 0, "watch does not pin its mount");
    unsigned char buffer[32], *next = buffer;
    check(read(fd, buffer, sizeof(buffer)) == sizeof(buffer), "unmount retires watch");
    event(&next, buffer + sizeof(buffer), wd, IN_UNMOUNT | IN_ISDIR, "");
    event(&next, buffer + sizeof(buffer), wd, IN_IGNORED, "");
    empty(fd);
    check(close(fd) == 0, "close unmount instance");
    puts("INOTIFY_UNMOUNT_PASS");
}

int main(int argc, char** argv) {
    if (argc == 4 && strcmp(argv[1], "--exec-reader") == 0)
        return exec_reader(atoi(argv[2]), atoi(argv[3]));
    check(argc >= 2 && argc <= 4, "usage: inotify-test directory [--legacy-seek] [--ordinary]");
    check(argv[1][0] == '/', "absolute fixture path");
    int legacy_seek = 0;
    for (int index = 2; index < argc; ++index) {
        if (strcmp(argv[index], "--unmount") == 0) {
            check(argc == 3, "standalone unmount test");
            unmount_event(argv[1]);
            return 0;
        }
        if (strcmp(argv[index], "--legacy-seek") == 0)
            legacy_seek = 1;
        else {
            check(strcmp(argv[index], "--ordinary") == 0, "known test option");
            check(setgid(65534) == 0 && setuid(65534) == 0, "ordinary caller");
        }
    }
    check(mkdir(argv[1], 0700) == 0, "create test directory");
    descriptor(legacy_seek);
    namespace_events(argv[1]);
    readiness(argv[1]);
    excluded_and_copy_fault(argv[1]);
    attributes(argv[1]);
    wait_and_lifetime(argv[0], argv[1]);
    check(rmdir(argv[1]) == 0, "retire empty fixture");
    printf("INOTIFY_PASS uid=%lu cases=6\n", (unsigned long)getuid());
    return 0;
}
