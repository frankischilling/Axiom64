// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/home.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "ACCOUNT_HOME_FAIL line=%d errno=%d\n", __LINE__, errno);              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum failure {
    NONE,
    MKDIR_BEFORE,
    MKDIR_AFTER,
    OPEN_BEFORE,
    CHOWN_AFTER,
    SYNC_AFTER,
    RENAME_BEFORE,
    RENAME_AFTER,
    COLLISION,
    SUBSTITUTE,
    UNLINK_BEFORE,
    UNLINK_AFTER
};
static enum failure failure;
static int directory, sync_target, sync_count;
static unsigned observations;
static char temporary[40], pathname[4096];

int __real_mkdirat(int, const char*, mode_t);
int __real_openat(int, const char*, int, ...);
int __real_fchown(int, uid_t, gid_t);
int __real_fsync(int);
long __real_syscall(long, ...);
int __real_unlinkat(int, const char*, int);

static int io_error(void) {
    failure = NONE;
    errno = EIO;
    return -1;
}

static void data(int parent, const char* name) {
    int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0 && write(fd, "preserved", 9) == 9 && close(fd) == 0);
}

int __wrap_mkdirat(int parent, const char* name, mode_t mode) {
    int staging = !strncmp(name, ".home-", 6);
    if (staging) {
        CHECK(strlen(name) < sizeof(temporary));
        strcpy(temporary, name);
    }
    if (staging && failure == MKDIR_BEFORE)
        return io_error();
    int result = __real_mkdirat(parent, name, mode);
    return !result && staging && failure == MKDIR_AFTER ? io_error() : result;
}

int __wrap_openat(int parent, const char* name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    if (failure == OPEN_BEFORE && !strcmp(name, temporary))
        return io_error();
    return __real_openat(parent, name, flags, mode);
}

int __wrap_fchown(int fd, uid_t uid, gid_t gid) {
    int result = __real_fchown(fd, uid, gid);
    if (!result && failure == CHOWN_AFTER)
        return io_error();
    if (!result && failure == SUBSTITUTE) {
        failure = NONE;
        CHECK(renameat(directory, temporary, directory, "displaced-stage") == 0);
        CHECK(__real_mkdirat(directory, temporary, 0700) == 0);
        int foreign = __real_openat(directory, temporary, O_RDONLY | O_DIRECTORY);
        CHECK(foreign >= 0);
        data(foreign, "marker");
        CHECK(close(foreign) == 0);
    }
    return result;
}

int __wrap_fsync(int fd) {
    int result = __real_fsync(fd);
    return !result && failure == SYNC_AFTER && ++sync_count == sync_target ? io_error() : result;
}

long __wrap_syscall(long number, ...) {
    CHECK(number == SYS_renameat2);
    va_list args;
    va_start(args, number);
    int from = va_arg(args, int);
    const char* source = va_arg(args, const char*);
    int to = va_arg(args, int);
    const char* target = va_arg(args, const char*);
    unsigned flags = va_arg(args, unsigned);
    va_end(args);
    CHECK(flags == 1);
    if (failure == RENAME_BEFORE)
        return io_error();
    if (failure == COLLISION) {
        failure = NONE;
        CHECK(__real_mkdirat(to, target, 0700) == 0);
        int foreign = __real_openat(to, target, O_RDONLY | O_DIRECTORY);
        CHECK(foreign >= 0 && __real_fchown(foreign, 2000, 2000) == 0);
        data(foreign, "marker");
        CHECK(close(foreign) == 0);
    }
    long result = __real_syscall(number, from, source, to, target, flags);
    return !result && failure == RENAME_AFTER ? io_error() : result;
}

int __wrap_unlinkat(int parent, const char* name, int flags) {
    if (failure == UNLINK_BEFORE)
        return io_error();
    int result = __real_unlinkat(parent, name, flags);
    return !result && failure == UNLINK_AFTER ? io_error() : result;
}

static unsigned descriptors(void) {
    unsigned count = 0;
    // This controlled fixture starts with standard streams and opens only low
    // descriptors. The range also covers the kernel's complete file table.
    for (int fd = 0; fd < 1024; fd++) {
        if (fcntl(fd, F_GETFD) >= 0)
            count++;
        else
            CHECK(errno == EBADF);
    }
    return count;
}

static void observed(const char* name, unsigned baseline) {
    CHECK(descriptors() == baseline);
    printf("ACCOUNT_HOME_OBSERVATION case=%s\n", name);
    observations++;
}

static void path(const char* root, const char* name) {
    CHECK(snprintf(pathname, sizeof(pathname), "%s/%s", root, name) < (int)sizeof(pathname));
}

static int absent(const char* name) {
    struct stat value;
    return fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}

static struct stat metadata(const char* name) {
    struct stat value;
    CHECK(fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) == 0);
    return value;
}

static void identity(const char* name, struct stat expected) {
    struct stat actual = metadata(name);
    CHECK(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino &&
          actual.st_uid == expected.st_uid && actual.st_gid == expected.st_gid &&
          actual.st_mode == expected.st_mode);
}

static void marker(const char* name) {
    int parent = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    CHECK(parent >= 0);
    int fd = openat(parent, "marker", O_RDONLY | O_NOFOLLOW);
    char bytes[10] = {0};
    CHECK(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 9 && !strcmp(bytes, "preserved"));
    CHECK(close(fd) == 0 && close(parent) == 0);
}

static struct account_home* create(const char* root, const char* name) {
    path(root, name);
    struct account_home* home = NULL;
    CHECK(account_home_create(pathname, 1000, 1000, &home) == 0 && home);
    struct stat value = metadata(name);
    CHECK(S_ISDIR(value.st_mode) && (value.st_mode & 07777) == 0700 && value.st_uid == 1000 &&
          value.st_gid == 1000 && absent(temporary));
    return home;
}

static void interrupted(const char* root, const char* name, enum failure selected, int unproven) {
    unsigned baseline = descriptors();
    path(root, name);
    failure = selected;
    sync_count = 0;
    struct account_home* home = NULL;
    CHECK(account_home_create(pathname, 1000, 1000, &home) == -1 && errno == EIO && home);
    failure = NONE;
    if (selected == RENAME_AFTER || (selected == SYNC_AFTER && sync_target == 3))
        CHECK(!absent(name) && absent(temporary));
    else
        CHECK(absent(name));
    if (unproven) {
        struct stat original = metadata(temporary);
        CHECK(account_home_finish(home, 0) == -1 && errno == EIO);
        identity(temporary, original);
        CHECK(S_ISDIR(original.st_mode) && original.st_uid == 0 &&
              (original.st_mode & 07777) == 0700);
    } else {
        CHECK(account_home_finish(home, 0) == 0);
        CHECK(absent(name) && absent(temporary));
    }
    CHECK(descriptors() == baseline);
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    CHECK(argc == 2 && argv[1][0] == '/' && mkdir(argv[1], 0755) == 0);
    directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(directory >= 0);
    unsigned baseline = descriptors();
    struct account_home* home = create(argv[1], "published");
    struct stat original = metadata("published");
    CHECK(account_home_finish(home, 1) == 0);
    identity("published", original);
    observed("published-home-retains-owned-inode", baseline);

    home = create(argv[1], "rollback");
    CHECK(account_home_finish(home, 0) == 0 && absent("rollback"));
    observed("unpublished-empty-home-removed", baseline);

    const char* existing[] = {"root-empty", "same-owner", "nonempty", "symlink", "file"};
    for (unsigned i = 0; i < 5; i++) {
        if (i < 3) {
            CHECK(mkdirat(directory, existing[i], 0700) == 0);
            int fd = openat(directory, existing[i], O_RDONLY | O_DIRECTORY);
            CHECK(fd >= 0);
            if (i == 1)
                CHECK(fchown(fd, 1000, 1000) == 0);
            if (i == 2)
                data(fd, "marker");
            CHECK(close(fd) == 0);
        } else if (i == 3)
            CHECK(symlinkat("nonempty", directory, existing[i]) == 0);
        else
            data(directory, existing[i]);
        original = metadata(existing[i]);
        path(argv[1], existing[i]);
        home = NULL;
        CHECK(account_home_create(pathname, 1000, 1000, &home) == -1 && errno == EEXIST);
        CHECK(account_home_finish(home, 0) == 0);
        identity(existing[i], original);
    }
    marker("nonempty");
    observed("all-existing-entries-preserved", baseline);

    home = create(argv[1], "substituted");
    original = metadata("substituted");
    CHECK(renameat(directory, "substituted", directory, "displaced-final") == 0);
    CHECK(mkdirat(directory, "substituted", 0700) == 0);
    int foreign = openat(directory, "substituted", O_RDONLY | O_DIRECTORY);
    CHECK(foreign >= 0 && fchown(foreign, 1000, 1000) == 0);
    data(foreign, "marker");
    CHECK(close(foreign) == 0);
    struct stat replacement = metadata("substituted");
    CHECK(account_home_finish(home, 0) == -1 && errno == ESTALE);
    identity("substituted", replacement);
    identity("displaced-final", original);
    marker("substituted");
    observed("same-owner-replacement-preserves-both-inodes", baseline);

    home = create(argv[1], "own-data");
    foreign = openat(directory, "own-data", O_RDONLY | O_DIRECTORY);
    CHECK(foreign >= 0);
    data(foreign, "marker");
    CHECK(close(foreign) == 0);
    original = metadata("own-data");
    CHECK(account_home_finish(home, 0) == -1 && errno == ENOTEMPTY);
    identity("own-data", original);
    marker("own-data");
    observed("owned-nonempty-home-is-preserved", baseline);

    CHECK(mkdirat(directory, "writable", 01777) == 0 &&
          fchmodat(directory, "writable", 01777, 0) == 0);
    path(argv[1], "writable/home");
    home = NULL;
    CHECK(account_home_create(pathname, 1000, 1000, &home) == -1 && errno == EACCES && !home);
    CHECK(symlinkat("published", directory, "ancestor") == 0);
    path(argv[1], "ancestor/home");
    CHECK(account_home_create(pathname, 1000, 1000, &home) == -1 && !home);
    observed("untrusted-final-parent-and-symlink-denied", baseline);

    for (unsigned i = 0; i < 2; i++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            if (i)
                CHECK(setfsuid(2000) == 0);
            else
                CHECK(setgroups(0, NULL) == 0 && setgid(2000) == 0 && setuid(2000) == 0);
            path(argv[1], "ordinary");
            home = NULL;
            CHECK(account_home_create(pathname, 1000, 1000, &home) == -1 && errno == EPERM &&
                  !home);
            _exit(0);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(absent("ordinary"));
    observed("ordinary-and-filesystem-identities-denied", baseline);

    interrupted(argv[1], "mkdir-before", MKDIR_BEFORE, 0);
    observed("failed-mkdir-without-mutation-leaves-no-home", baseline);
    interrupted(argv[1], "mkdir-after", MKDIR_AFTER, 1);
    observed("late-mkdir-preserves-unproven-private-stage", baseline);
    interrupted(argv[1], "open-before", OPEN_BEFORE, 1);
    observed("failed-open-preserves-unproven-private-stage", baseline);
    interrupted(argv[1], "chown-after", CHOWN_AFTER, 0);
    observed("late-chown-removes-only-held-stage", baseline);
    for (int i = 1; i <= 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "sync-after-%d", i);
        sync_target = i;
        interrupted(argv[1], name, SYNC_AFTER, 0);
    }
    observed("all-creation-sync-errors-release-owned-home", baseline);
    interrupted(argv[1], "rename-before", RENAME_BEFORE, 0);
    interrupted(argv[1], "rename-after", RENAME_AFTER, 0);
    observed("early-and-late-rename-errors-release-owned-home", baseline);

    failure = COLLISION;
    path(argv[1], "collision");
    home = NULL;
    CHECK(account_home_create(pathname, 1000, 1000, &home) == -1 && errno == EEXIST && home);
    original = metadata("collision");
    CHECK(original.st_uid == 2000 && original.st_gid == 2000);
    CHECK(account_home_finish(home, 0) == 0 && absent(temporary));
    identity("collision", original);
    marker("collision");
    observed("publication-collision-preserves-foreign-home", baseline);

    failure = SUBSTITUTE;
    path(argv[1], "stage-substitution");
    home = NULL;
    CHECK(account_home_create(pathname, 1000, 1000, &home) == -1 && errno == ESTALE && home);
    original = metadata(temporary);
    CHECK(account_home_finish(home, 0) == -1 && errno == ESTALE);
    identity(temporary, original);
    marker(temporary);
    CHECK(!absent("displaced-stage") && absent("stage-substitution"));
    observed("staging-substitution-preserves-both-inodes", baseline);

    for (unsigned i = 0; i < 2; i++) {
        const char* name = i ? "unlink-after" : "unlink-before";
        home = create(argv[1], name);
        original = metadata(name);
        failure = i ? UNLINK_AFTER : UNLINK_BEFORE;
        CHECK(account_home_finish(home, 0) == -1 && errno == EIO);
        if (i)
            CHECK(absent(name));
        else
            identity(name, original);
    }
    observed("early-and-late-cleanup-errors-are-reported", baseline);
    home = create(argv[1], "cleanup-sync");
    failure = SYNC_AFTER;
    sync_count = 0;
    sync_target = 1;
    CHECK(account_home_finish(home, 0) == -1 && errno == EIO && absent("cleanup-sync"));
    observed("cleanup-durability-error-is-reported", baseline);
    CHECK(account_home_finish(NULL, 0) == 0 && fsync(directory) == 0 && close(directory) == 0);
    printf("ACCOUNT_HOME_PASS observations=%u\n", observations);
    return 0;
}
