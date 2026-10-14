// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned observations;
#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "PATH_DESCRIPTOR_FAIL line=%d errno=%d expression=%s\n", __LINE__,     \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
        observations++;                                                                            \
    } while (0)
#define DENIED(expression)                                                                         \
    do {                                                                                           \
        errno = 0;                                                                                 \
        CHECK((expression) == -1 && errno == EBADF);                                               \
    } while (0)

static void target(int fd, const char* expected) {
    char value[64] = {0};
    ssize_t size = readlinkat(fd, "", value, sizeof(value));
    CHECK(size == (ssize_t)strlen(expected) && !memcmp(value, expected, (size_t)size));
}

static void record_conflict(int fd, short expected, pid_t owner) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct flock query = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        CHECK(fcntl(fd, F_GETLK, &query) == 0 && query.l_type == expected &&
              (expected == F_UNLCK || query.l_pid == owner));
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
}

static void record_close_policy(void) {
    int data = open("data", O_RDWR | O_CLOEXEC);
    CHECK(data >= 0);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    CHECK(fcntl(data, F_SETLK, &lock) == 0);
    int path = open("data", O_PATH | O_CLOEXEC);
    CHECK(path >= 0 && close(path) == 0);
    record_conflict(data, F_WRLCK, getpid());
    int ordinary = open("data", O_RDONLY | O_CLOEXEC);
    CHECK(ordinary >= 0 && close(ordinary) == 0);
    record_conflict(data, F_UNLCK, getpid());
    CHECK(close(data) == 0);
    puts("PATH_DESCRIPTOR_RECORD_CLOSE_PASS path_preserved=1 ordinary_released=1");
}

int main(int argc, char** argv) {
    CHECK((argc == 2 || (argc == 3 && !strcmp(argv[2], "mounted-block"))) && !getuid() &&
          !getgid());
    CHECK(mkdir(argv[1], 0755) == 0 && chmod(argv[1], 0755) == 0 && chdir(argv[1]) == 0);
    int file = open("data", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    CHECK(file >= 0 && write(file, "fixture", 7) == 7 && close(file) == 0);
    CHECK(symlink("data", "current") == 0 && symlink("replacement", "next") == 0);
    int link = open("current", O_PATH | O_NOFOLLOW | O_CLOEXEC);
    CHECK(link >= 0);
    struct stat before, after;
    CHECK(fstat(link, &before) == 0 && S_ISLNK(before.st_mode) && before.st_nlink == 1);
    CHECK(fcntl(link, F_GETFL) == (O_PATH | O_NOFOLLOW));
    CHECK(fcntl(link, F_GETFD) == FD_CLOEXEC);
    target(link, "data");
    CHECK(rename("next", "current") == 0);
    CHECK(fstat(link, &after) == 0 && after.st_dev == before.st_dev &&
          after.st_ino == before.st_ino && after.st_nlink == 0);
    target(link, "data");
    char value[64] = {0};
    CHECK(readlink("current", value, sizeof(value)) == 11 && !memcmp(value, "replacement", 11));
    CHECK(close(link) == 0);

    int descriptor = open("data", O_PATH | O_CLOEXEC | O_TRUNC | O_RDWR | O_NONBLOCK | O_APPEND);
    CHECK(descriptor >= 0 && fcntl(descriptor, F_GETFL) == O_PATH);
    CHECK(fstat(descriptor, &after) == 0 && after.st_size == 7);
    struct statfs filesystem;
    CHECK(fstatfs(descriptor, &filesystem) == 0);
    if (argc == 3) {
        int device = open("/dev/vda", O_PATH | O_CLOEXEC);
        CHECK(device >= 0);
        CHECK(fstat(device, &after) == 0 && S_ISBLK(after.st_mode));
        DENIED(read(device, value, 1));
        CHECK(close(device) == 0);
    }
    record_close_policy();
    DENIED(read(descriptor, value, 1));
    DENIED(read(descriptor, value, 0));
    DENIED(write(descriptor, value, 1));
    DENIED(pread(descriptor, value, 1, 0));
    DENIED(pwrite(descriptor, value, 1, 0));
    DENIED(lseek(descriptor, 0, SEEK_SET));
    DENIED(ftruncate(descriptor, 0));
    DENIED(fsync(descriptor));
    DENIED(fdatasync(descriptor));
    // Compare the Linux syscalls directly; libc may retry through /proc/self/fd.
    DENIED(syscall(SYS_fchmod, descriptor, 0600));
    DENIED(syscall(SYS_fchown, descriptor, 0, 0));
    DENIED(ioctl(descriptor, FIONREAD, value));
    DENIED(flock(descriptor, LOCK_EX | LOCK_NB));
    DENIED(fcntl(descriptor, F_SETFL, O_NONBLOCK));
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, descriptor, 0) == MAP_FAILED && errno == EBADF);
    struct pollfd readiness = {.fd = descriptor, .events = POLLIN | POLLOUT};
    CHECK(poll(&readiness, 1, 0) == 1 && readiness.revents == POLLNVAL);
    fd_set ready;
    FD_ZERO(&ready);
    FD_SET(descriptor, &ready);
    struct timeval immediate = {0};
    int selected = select(descriptor + 1, &ready, NULL, NULL, &immediate);
    printf("PATH_DESCRIPTOR_SELECT result=%d requested_bit=%d\n", selected,
           !!FD_ISSET(descriptor, &ready));
    CHECK(selected == 1 && FD_ISSET(descriptor, &ready));
    int events = epoll_create1(EPOLL_CLOEXEC);
    CHECK(events >= 0);
    struct epoll_event event = {.events = EPOLLIN};
    DENIED(epoll_ctl(events, EPOLL_CTL_ADD, descriptor, &event));
    CHECK(close(events) == 0);
    struct sockaddr address = {0};
    socklen_t address_size = sizeof(address);
    DENIED(getsockname(descriptor, &address, &address_size));
    DENIED(listen(descriptor, 1));
    int copy = dup(descriptor);
    CHECK(copy >= 0 && fcntl(copy, F_GETFL) == O_PATH && fcntl(copy, F_GETFD) == 0);
    CHECK(fcntl(copy, F_SETFD, FD_CLOEXEC) == 0 && fcntl(copy, F_GETFD) == FD_CLOEXEC);
    CHECK(close(copy) == 0 && close(descriptor) == 0);
    errno = 0;
    CHECK(open("absent", O_PATH | O_CREAT | O_RDWR, 0600) == -1 && errno == ENOENT);
    errno = 0;
    CHECK(lstat("absent", &after) == -1 && errno == ENOENT);
    CHECK(symlink("missing", "dangling") == 0);
    descriptor = open("dangling", O_PATH | O_NOFOLLOW);
    CHECK(descriptor >= 0);
    target(descriptor, "missing");
    CHECK(close(descriptor) == 0);

    descriptor = open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
    CHECK(descriptor >= 0 && fchdir(descriptor) == 0);
    CHECK(fstatat(descriptor, "", &after, AT_EMPTY_PATH) == 0 && S_ISDIR(after.st_mode));
    DENIED(syscall(SYS_getdents64, descriptor, value, sizeof(value)));
    CHECK(close(descriptor) == 0 && chmod("data", 0000) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        errno = 0;
        CHECK(open("data", O_RDONLY) == -1 && errno == EACCES);
        int path = open("data", O_PATH);
        CHECK(path >= 0 && fstat(path, &after) == 0 && after.st_uid == 0 && after.st_size == 7);
        DENIED(read(path, value, 1));
        errno = 0;
        CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, path, 0) == MAP_FAILED && errno == EBADF);
        CHECK(close(path) == 0);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    printf("PATH_DESCRIPTOR_PASS root_observations=%u ordinary_permission_checks=6 "
           "record_lock_child_checks=2\n",
           observations);
    return 0;
}
