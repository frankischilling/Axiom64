// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "RENAME_FAIL line=%d errno=%d\n", __LINE__, errno);                    \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
#define ERROR(value, code)                                                                         \
    do {                                                                                           \
        errno = 0;                                                                                 \
        CHECK((value) == -1 && errno == (code));                                                   \
    } while (0)

static unsigned observations;

static void observed(const char* name) {
    printf("RENAME_OBSERVATION case=%s\n", name);
    observations++;
}

static int move(int from, const char* source, int to, const char* target, unsigned long flags) {
    return (int)syscall(SYS_renameat2, from, source, to, target, flags);
}

static int file(int directory, const char* name, const char* content) {
    int fd = openat(directory, name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    CHECK(fd >= 0 && write(fd, content, strlen(content)) == (ssize_t)strlen(content));
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    return fd;
}

static void contents(int fd, const char* expected) {
    char bytes[64] = {0};
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(read(fd, bytes, sizeof(bytes)) == (ssize_t)strlen(expected) && !strcmp(bytes, expected));
}

static void identity(int directory, const char* name, int fd) {
    struct stat actual, expected;
    CHECK(fstat(fd, &expected) == 0 && fstatat(directory, name, &actual, AT_SYMLINK_NOFOLLOW) == 0);
    CHECK(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino);
}

static void race(int directory, unsigned index) {
    char first[32], second[32], target[32];
    snprintf(first, sizeof(first), "first-%u", index);
    snprintf(second, sizeof(second), "second-%u", index);
    snprintf(target, sizeof(target), "winner-%u", index);
    int one = file(directory, first, "first"), two = file(directory, second, "second");
    int gate[2], result[2];
    CHECK(pipe(gate) == 0 && pipe(result) == 0);
    pid_t children[2];
    for (unsigned i = 0; i < 2; i++) {
        children[i] = fork();
        CHECK(children[i] >= 0);
        if (!children[i]) {
            CHECK(close(gate[1]) == 0 && close(result[0]) == 0);
            char token;
            CHECK(read(gate[0], &token, 1) == 1);
            int status = move(directory, i ? second : first, directory, target, 1);
            unsigned char reply[2] = {(unsigned char)i, status == 0 ? 0 : errno == EEXIST ? 1 : 2};
            CHECK(write(result[1], reply, sizeof(reply)) == sizeof(reply));
            _exit(0);
        }
    }
    CHECK(close(gate[0]) == 0 && close(result[1]) == 0);
    CHECK(write(gate[1], "go", 2) == 2 && close(gate[1]) == 0);
    unsigned char replies[4];
    size_t used = 0;
    while (used < sizeof(replies)) {
        ssize_t count = read(result[0], replies + used, sizeof(replies) - used);
        CHECK(count > 0);
        used += (size_t)count;
    }
    CHECK(close(result[0]) == 0 && replies[0] != replies[2]);
    CHECK((replies[1] == 0 && replies[3] == 1) || (replies[1] == 1 && replies[3] == 0));
    unsigned winner = replies[1] == 0 ? replies[0] : replies[2];
    identity(directory, target, winner ? two : one);
    identity(directory, winner ? first : second, winner ? one : two);
    contents(one, "first");
    contents(two, "second");
    for (unsigned i = 0; i < 2; i++) {
        int status;
        CHECK(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0);
    }
    CHECK(close(one) == 0 && close(two) == 0);
    CHECK(unlinkat(directory, target, 0) == 0);
    CHECK(unlinkat(directory, winner ? first : second, 0) == 0);
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    CHECK(argc == 2 && argv[1][0] == '/' && mkdir(argv[1], 0700) == 0);
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(directory >= 0);
    int source = file(directory, "source", "source"), target = file(directory, "target", "target");
    ERROR(move(directory, "source", directory, "target", 1), EEXIST);
    identity(directory, "source", source);
    identity(directory, "target", target);
    contents(source, "source");
    contents(target, "target");
    observed("existing-file-preserved");
    ERROR(move(directory, "source", directory, "source", 1), EEXIST);
    CHECK(linkat(directory, "source", directory, "alias", 0) == 0);
    ERROR(move(directory, "source", directory, "alias", 1), EEXIST);
    observed("same-name-and-hardlink-preserved");
    CHECK(symlinkat("absent", directory, "dangling") == 0);
    ERROR(move(directory, "source", directory, "dangling", 1), EEXIST);
    observed("dangling-symlink-preserved");
    CHECK(mkdirat(directory, "empty", 0700) == 0);
    CHECK(mkdirat(directory, "occupied", 0700) == 0);
    int empty = openat(directory, "empty", O_RDONLY | O_DIRECTORY);
    int occupied = openat(directory, "occupied", O_RDONLY | O_DIRECTORY);
    CHECK(empty >= 0 && occupied >= 0);
    int data = file(occupied, "data", "retained");
    ERROR(move(directory, "empty", directory, "occupied", 1), EEXIST);
    identity(directory, "empty", empty);
    identity(directory, "occupied", occupied);
    contents(data, "retained");
    observed("existing-directory-and-data-preserved");
    CHECK(move(directory, "empty", directory, "home", 1) == 0);
    identity(directory, "home", empty);
    observed("directory-published-to-absent-name");
    CHECK(move(directory, "source", directory, "new", 1) == 0);
    identity(directory, "new", source);
    observed("file-published-to-absent-name");
    CHECK(move(directory, "new", directory, "target", 0) == 0);
    identity(directory, "target", source);
    contents(target, "target");
    observed("zero-flags-keeps-replacement-semantics");
    ERROR(move(directory, "missing", directory, "missing-target", 1), ENOENT);
    ERROR(move(-1, "target", directory, "missing-target", 1), EBADF);
    ERROR(move(directory, "target", -1, "missing-target", 1), EBADF);
    ERROR(move(directory, (const char*)1, directory, "missing-target", 1), EFAULT);
    ERROR(move(directory, "target", directory, (const char*)1, 1), EFAULT);
    ERROR(move(directory, "target", directory, "missing-target", 3), EINVAL);
    ERROR(move(directory, "target", directory, "missing-target", 6), EINVAL);
    ERROR(move(directory, "target", directory, "missing-target", 8), EINVAL);
    ERROR(move(directory, "target", directory, "target", 1ul | (1ul << 32)), EEXIST);
    ERROR(move(directory, ".", directory, "missing-target", 1), EBUSY);
    ERROR(move(directory, "target", directory, ".", 1), EEXIST);
    ERROR(move(directory, "target", directory, "missing-target/", 1), ENOTDIR);
    CHECK(move(directory, "home", directory, "missing-target/", 1) == 0);
    identity(directory, "missing-target", empty);
    CHECK(move(directory, "missing-target", directory, "home", 0) == 0);
    observed("paths-flags-and-scalar-width-errors");
    CHECK(fchmod(directory, 0755) == 0);
    pid_t ordinary = fork();
    CHECK(ordinary >= 0);
    if (!ordinary) {
        CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        ERROR(move(directory, "target", directory, "occupied", 1), EEXIST);
        ERROR(move(directory, "target", directory, "permission-target", 1), EACCES);
        _exit(0);
    }
    int ordinary_status;
    CHECK(waitpid(ordinary, &ordinary_status, 0) == ordinary && WIFEXITED(ordinary_status) &&
          WEXITSTATUS(ordinary_status) == 0);
    CHECK(fchmod(directory, 0700) == 0);
    identity(directory, "target", source);
    identity(directory, "occupied", occupied);
    observed("ordinary-publication-requires-parent-write");
    for (unsigned i = 0; i < 32; i++)
        race(directory, i);
    observed("concurrent-publish-has-exactly-one-winner");
    CHECK(close(source) == 0 && close(target) == 0 && close(empty) == 0 && close(occupied) == 0 &&
          close(data) == 0 && fsync(directory) == 0 && close(directory) == 0);
    printf("RENAME_PASS observations=%u concurrent_publications=32\n", observations);
    return 0;
}
