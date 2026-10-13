// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/store.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "ACCOUNT_TRANSACTION_FAIL line=%d errno=%d\n", __LINE__, errno);       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum boundary {
    NONE,
    STAGED_INTENT,
    PUBLISHED_INTENT,
    STAGED_HOME,
    PUBLISHED_HOME,
    CLAIMED_GENERATION,
    PARTIAL_GENERATION,
    PUBLISHED_CURRENT,
    LATE_RENAME,
    SHORT_WRITE,
    UNPROVEN_INTENT,
    UNPROVEN_GENERATION
};
static enum boundary boundary;
static int gate, store_fd = -1, intent_fd = -1, generation_fd = -1, shadow_fd = -1,
                 home_parent = -1;
static int seen_home;
static unsigned observations;
static char store_path[4096], home_path[4096], case_path[4096];
static const char* file_names[] = {"passwd", "group", "shadow"};
static const char* old_text[] = {"root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\n",
                                 "root:!:::::::\n"};
static const char* new_text[] = {
    "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\n",
    "root:x:0:\nalice:x:1000:alice\n", "root:!:::::::\nalice:!:::::::\n"};

int __real_openat(int, const char*, int, ...);
int __real_mkdirat(int, const char*, mode_t);
int __real_fsync(int);
int __real_fsetxattr(int, const char*, const void*, size_t, int);
ssize_t __real_write(int, const void*, size_t);
int __real_renameat(int, const char*, int, const char*);
long __real_syscall(long, ...);

static void checkpoint(void) {
    CHECK(__real_write(gate, "r", 1) == 1);
    for (;;)
        pause();
}

int __wrap_openat(int parent, const char* name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    int fd = __real_openat(parent, name, flags, mode);
    if (fd >= 0 && (flags & O_DIRECTORY) && !strcmp(name, "store"))
        store_fd = fd;
    if (fd >= 0 && (flags & O_CREAT) && !strcmp(name, "home-prepare")) {
        intent_fd = fd;
        if (boundary == UNPROVEN_INTENT) {
            CHECK(__real_fsync(fd) == 0 && __real_fsync(parent) == 0);
            checkpoint();
        }
    }
    if (fd >= 0 && seen_home && (flags & O_DIRECTORY) && !strncmp(name, "g-", 2)) {
        generation_fd = fd;
        if (boundary == UNPROVEN_GENERATION) {
            CHECK(__real_fsync(fd) == 0 && __real_fsync(parent) == 0);
            checkpoint();
        }
    }
    if (fd >= 0 && (flags & O_CREAT) && !strcmp(name, "shadow"))
        shadow_fd = fd;
    return fd;
}

int __wrap_mkdirat(int parent, const char* name, mode_t mode) {
    if (!strncmp(name, ".home-", 6))
        home_parent = parent;
    return __real_mkdirat(parent, name, mode);
}

int __wrap_fsync(int fd) {
    int result = __real_fsync(fd);
    if (!result && boundary == STAGED_INTENT && fd == intent_fd)
        checkpoint();
    return result;
}

int __wrap_fsetxattr(int fd, const char* name, const void* data, size_t size, int flags) {
    int result = __real_fsetxattr(fd, name, data, size, flags);
    if (!result && boundary == STAGED_HOME && !strcmp(name, "trusted.axiom64.home")) {
        CHECK(__real_fsync(fd) == 0 && __real_fsync(home_parent) == 0);
        checkpoint();
    }
    if (!result && boundary == CLAIMED_GENERATION && !strcmp(name, "trusted.axiom64.generation")) {
        CHECK(__real_fsync(fd) == 0 && __real_fsync(store_fd) == 0);
        checkpoint();
    }
    return result;
}

ssize_t __wrap_write(int fd, const void* data, size_t size) {
    if (fd == shadow_fd && (boundary == PARTIAL_GENERATION || boundary == SHORT_WRITE)) {
        CHECK(size >= 3 && __real_write(fd, data, 3) == 3);
        if (boundary == PARTIAL_GENERATION) {
            CHECK(__real_fsync(fd) == 0 && __real_fsync(generation_fd) == 0 &&
                  __real_fsync(store_fd) == 0);
            checkpoint();
        }
        boundary = NONE;
        errno = EIO;
        return -1;
    }
    return __real_write(fd, data, size);
}

int __wrap_renameat(int from, const char* source, int to, const char* target) {
    int result = __real_renameat(from, source, to, target);
    if (!result && !strcmp(target, "current")) {
        if (boundary == PUBLISHED_CURRENT) {
            CHECK(__real_fsync(to) == 0);
            checkpoint();
        }
        if (boundary == LATE_RENAME) {
            boundary = NONE;
            errno = EIO;
            return -1;
        }
    }
    return result;
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
    long result = __real_syscall(number, from, source, to, target, flags);
    if (!result && !strcmp(target, "home-intent") && boundary == PUBLISHED_INTENT) {
        CHECK(__real_fsync(to) == 0);
        checkpoint();
    }
    if (!result && !strncmp(source, ".home-", 6)) {
        seen_home = 1;
        if (boundary == PUBLISHED_HOME) {
            CHECK(__real_fsync(to) == 0);
            checkpoint();
        }
    }
    return result;
}

static void content(struct account_content files[ACCOUNT_FILE_COUNT], const char* const text[]) {
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        files[i] = (struct account_content){text[i], strlen(text[i])};
}

static void snapshot(const struct account_store* store, const char* const text[]) {
    const struct account_content* actual = account_store_snapshot(store);
    CHECK(actual);
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        CHECK(actual[i].size == strlen(text[i]) &&
              !memcmp(actual[i].data, text[i], actual[i].size));
}

static void observed(const char* name) {
    printf("ACCOUNT_TRANSACTION_OBSERVATION case=%s\n", name);
    observations++;
}

static void setup(const char* root, const char* name) {
    boundary = NONE;
    seen_home = 0;
    store_fd = intent_fd = generation_fd = shadow_fd = home_parent = -1;
    CHECK(snprintf(case_path, sizeof(case_path), "%s/%s", root, name) < (int)sizeof(case_path));
    CHECK(mkdir(case_path, 0755) == 0);
    CHECK(snprintf(store_path, sizeof(store_path), "%s/store", case_path) <
          (int)sizeof(store_path));
    CHECK(snprintf(home_path, sizeof(home_path), "%s/homes/alice", case_path) <
          (int)sizeof(home_path));
    struct account_store* store = NULL;
    CHECK(account_store_begin(store_path, 1, &store) == 0);
    struct account_content files[ACCOUNT_FILE_COUNT];
    content(files, old_text);
    int published;
    CHECK(account_store_commit(store, files, &published) == 0 && published == 1);
    account_store_end(store);
    store_fd = intent_fd = generation_fd = shadow_fd = home_parent = -1;
}

static int absent(const char* path) {
    struct stat value;
    return lstat(path, &value) < 0 && errno == ENOENT;
}

static int pending(const char* name) {
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s/%s", store_path, name) < (int)sizeof(path));
    return !absent(path);
}

static void killed(enum boundary selected) {
    int pipes[2];
    CHECK(pipe(pipes) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(pipes[0]) == 0);
        gate = pipes[1];
        boundary = selected;
        struct account_store* store = NULL;
        CHECK(account_store_begin(store_path, 0, &store) == 0);
        struct account_content files[ACCOUNT_FILE_COUNT];
        content(files, new_text);
        int published;
        account_store_commit_home(store, files, home_path, 1000, 1000, &published);
        CHECK(0);
    }
    CHECK(close(pipes[1]) == 0);
    char ready;
    CHECK(read(pipes[0], &ready, 1) == 1 && ready == 'r' && close(pipes[0]) == 0 &&
          kill(child, SIGKILL) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGKILL);
}

static void data(const char* directory, int creating) {
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s/data", directory) < (int)sizeof(path));
    int fd = open(path, creating ? O_CREAT | O_EXCL | O_WRONLY : O_RDONLY, 0600);
    CHECK(fd >= 0);
    char bytes[10] = {0};
    if (creating)
        CHECK(write(fd, "preserved", 9) == 9 && fsync(fd) == 0);
    else
        CHECK(read(fd, bytes, sizeof(bytes)) == 9 && !strcmp(bytes, "preserved"));
    CHECK(close(fd) == 0);
}

static void blocked(int error) {
    struct account_store* store = NULL;
    CHECK(account_store_begin(store_path, 0, &store) == 0 &&
          account_store_recovery_error(store) == error);
    snapshot(store, old_text);
    struct account_content files[ACCOUNT_FILE_COUNT];
    content(files, new_text);
    int published = 1;
    CHECK(account_store_commit(store, files, &published) == -1 && errno == error && published == 0);
    account_store_end(store);
    CHECK(pending("home-intent"));
}

static const char* reboot_phases[] = {
    "staged-intent",      "published-intent",   "staged-home",      "published-home",
    "claimed-generation", "partial-generation", "published-current"};

static void reboot_paths(const char* root, const char* name) {
    CHECK(snprintf(case_path, sizeof(case_path), "%s/%s", root, name) < (int)sizeof(case_path));
    CHECK(snprintf(store_path, sizeof(store_path), "%s/store", case_path) <
          (int)sizeof(store_path));
    CHECK(snprintf(home_path, sizeof(home_path), "%s/homes/alice", case_path) <
          (int)sizeof(home_path));
}

static void boot_id(char value[40]) {
    memset(value, 0, 40);
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && read(fd, value, 39) == 37 && close(fd) == 0 && value[36] == '\n');
}

static void reboot(const char* root, int create) {
    char path[4096], current[40];
    boot_id(current);
    CHECK(snprintf(path, sizeof(path), "%s/boot-id", root) < (int)sizeof(path));
    int fd = open(path, create ? O_CREAT | O_EXCL | O_WRONLY : O_RDONLY, 0600);
    CHECK(fd >= 0);
    if (create)
        CHECK(write(fd, current, 37) == 37 && fsync(fd) == 0);
    else {
        char saved[40] = {0};
        CHECK(read(fd, saved, sizeof(saved)) == 37 && strcmp(saved, current));
        observed("different-real-kernel-after-intent-publication");
    }
    CHECK(close(fd) == 0);
    for (unsigned i = 0; i < 7; i++) {
        if (create) {
            setup(root, reboot_phases[i]);
            killed((enum boundary)(i + 1));
            if (i == 6)
                data(home_path, 1);
        } else {
            reboot_paths(root, reboot_phases[i]);
            struct account_store* store = NULL;
            CHECK(account_store_begin(store_path, 0, &store) == 0 &&
                  !account_store_recovery_error(store));
            snapshot(store, i == 6 ? new_text : old_text);
            account_store_end(store);
            CHECK(!pending("home-intent") && !pending("home-prepare"));
            if (i == 6)
                data(home_path, 0);
            else
                CHECK(absent(home_path));
            observed(reboot_phases[i]);
        }
    }
    if (create) {
        setup(root, "nonempty");
        killed(PUBLISHED_HOME);
        data(home_path, 1);
        setup(root, "replacement");
        killed(PUBLISHED_HOME);
        char displaced[4096];
        CHECK(snprintf(displaced, sizeof(displaced), "%s/displaced", case_path) <
              (int)sizeof(displaced));
        CHECK(rename(home_path, displaced) == 0 && mkdir(home_path, 0700) == 0 &&
              chown(home_path, 1000, 1000) == 0);
        data(home_path, 1);
        puts("ACCOUNT_TRANSACTION_REBOOT_PREPARED cases=9");
    } else {
        reboot_paths(root, "nonempty");
        blocked(ENOTEMPTY);
        data(home_path, 0);
        observed("nonempty-pending-home-preserved-after-reboot");
        reboot_paths(root, "replacement");
        blocked(ESTALE);
        data(home_path, 0);
        observed("foreign-home-preserved-after-reboot");
        printf("ACCOUNT_TRANSACTION_REBOOT_PASS observations=%u\n", observations);
    }
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    if (argc == 3) {
        int create = !strcmp(argv[1], "create");
        CHECK(create || !strcmp(argv[1], "verify"));
        if (create)
            CHECK(mkdir(argv[2], 0755) == 0);
        reboot(argv[2], create);
        return 0;
    }
    CHECK(argc == 2 && mkdir(argv[1], 0755) == 0);
    const char* phases[] = {"staged-intent",    "published-intent",   "staged-home",
                            "published-home",   "claimed-generation", "partial-generation",
                            "published-current"};
    for (unsigned i = 0; i < 7; i++) {
        setup(argv[1], phases[i]);
        killed((enum boundary)(i + 1));
        if (i == 6)
            data(home_path, 1);
        struct account_store* store = NULL;
        CHECK(account_store_begin(store_path, 0, &store) == 0 &&
              !account_store_recovery_error(store));
        snapshot(store, i == 6 ? new_text : old_text);
        account_store_end(store);
        CHECK(!pending("home-intent") && !pending("home-prepare"));
        if (i == 6)
            data(home_path, 0);
        else
            CHECK(absent(home_path));
        observed(phases[i]);
    }
    setup(argv[1], "nonempty");
    killed(PUBLISHED_HOME);
    data(home_path, 1);
    blocked(ENOTEMPTY);
    data(home_path, 0);
    observed("nonempty-pending-home-keeps-data-and-old-readable-generation");

    setup(argv[1], "replacement");
    killed(PUBLISHED_HOME);
    char displaced[4096];
    CHECK(snprintf(displaced, sizeof(displaced), "%s/displaced", case_path) <
          (int)sizeof(displaced));
    CHECK(rename(home_path, displaced) == 0 && mkdir(home_path, 0700) == 0 &&
          chown(home_path, 1000, 1000) == 0);
    data(home_path, 1);
    blocked(ESTALE);
    data(home_path, 0);
    CHECK(!absent(displaced));
    observed("foreign-same-owner-home-and-displaced-inode-preserved");

    const char* invalid_names[] = {"bad-claim", "bad-record", "short-claim"};
    const char* invalid_observations[] = {"wrong-intent-authority-preserved",
                                          "malformed-intent-preserved",
                                          "short-intent-authority-preserved"};
    for (unsigned i = 0; i < 3; i++) {
        setup(argv[1], invalid_names[i]);
        killed(PUBLISHED_HOME);
        char path[4096];
        CHECK(snprintf(path, sizeof(path), "%s/home-intent", store_path) < (int)sizeof(path));
        if (i != 1) {
            unsigned char wrong[16] = {1};
            CHECK(setxattr(path, "trusted.axiom64.intent", wrong, i ? 8 : sizeof(wrong), 0) == 0);
        } else {
            int fd = open(path, O_WRONLY);
            CHECK(fd >= 0 && pwrite(fd, "X", 1, 0) == 1 && close(fd) == 0);
        }
        struct account_store* store = NULL;
        CHECK(account_store_begin(store_path, 0, &store) == -1 &&
              errno == (i == 1 ? EUCLEAN : ESTALE) && !store);
        CHECK(pending("home-intent") && !absent(home_path));
        observed(invalid_observations[i]);
    }
    setup(argv[1], "unknown-current");
    killed(PUBLISHED_HOME);
    int parent = open(store_path, O_RDONLY | O_DIRECTORY);
    const char foreign[] = "g-11111111111111111111111111111111";
    CHECK(parent >= 0 && mkdirat(parent, foreign, 0755) == 0);
    int generation = openat(parent, foreign, O_RDONLY | O_DIRECTORY);
    CHECK(generation >= 0);
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++) {
        int fd = openat(generation, file_names[i], O_CREAT | O_EXCL | O_WRONLY,
                        i == ACCOUNT_SHADOW ? 0600 : 0644);
        CHECK(fd >= 0 &&
              write(fd, old_text[i], strlen(old_text[i])) == (ssize_t)strlen(old_text[i]) &&
              close(fd) == 0);
    }
    CHECK(close(generation) == 0 && unlinkat(parent, "current", 0) == 0 &&
          symlinkat(foreign, parent, "current") == 0 && close(parent) == 0);
    struct account_store* store = NULL;
    CHECK(account_store_begin(store_path, 0, &store) == -1 && errno == EUCLEAN && !store &&
          pending("home-intent") && !absent(home_path));
    observed("unexpected-generation-does-not-authorize-home-deletion");

    setup(argv[1], "late-rename");
    CHECK(account_store_begin(store_path, 0, &store) == 0);
    struct account_content files[ACCOUNT_FILE_COUNT];
    content(files, new_text);
    int published = 0;
    boundary = LATE_RENAME;
    CHECK(account_store_commit_home(store, files, home_path, 1000, 1000, &published) == -1 &&
          errno == EIO && published == 1);
    account_store_end(store);
    boundary = NONE;
    CHECK(account_store_begin(store_path, 0, &store) == 0 && !account_store_recovery_error(store));
    snapshot(store, new_text);
    account_store_end(store);
    CHECK(!absent(home_path));
    observed("visible-current-after-reported-rename-error-is-kept");

    for (unsigned i = 0; i < 2; i++) {
        setup(argv[1], i ? "masked-short-write" : "short-write");
        mode_t previous = umask(i ? 0777 : 0022);
        CHECK(account_store_begin(store_path, 0, &store) == 0);
        boundary = SHORT_WRITE;
        CHECK(account_store_commit_home(store, files, home_path, 1000, 1000, &published) == -1 &&
              errno == EIO && published == 0);
        account_store_end(store);
        umask(previous);
        CHECK(account_store_begin(store_path, 0, &store) == 0 &&
              !account_store_recovery_error(store));
        snapshot(store, old_text);
        account_store_end(store);
        CHECK(absent(home_path) && !pending("home-intent"));
    }
    observed("short-write-rollback-and-restrictive-umask-release-owned-state");

    setup(argv[1], "unproven-intent");
    killed(UNPROVEN_INTENT);
    CHECK(account_store_begin(store_path, 0, &store) == -1 && errno == ESTALE && !store);
    CHECK(pending("home-prepare") && !pending("home-intent") && absent(home_path));
    observed("unproven-intent-staging-file-preserved");
    setup(argv[1], "unproven-generation");
    killed(UNPROVEN_GENERATION);
    blocked(ESTALE);
    observed("unproven-generation-preserved-with-writes-blocked");

    setup(argv[1], "ordinary");
    killed(PUBLISHED_HOME);
    pid_t ordinary = fork();
    CHECK(ordinary >= 0);
    if (!ordinary) {
        CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        char path[4096];
        CHECK(snprintf(path, sizeof(path), "%s/home-intent", store_path) < (int)sizeof(path));
        CHECK(open(path, O_RDONLY) == -1 && errno == EACCES);
        CHECK(open(path, O_WRONLY) == -1 && errno == EACCES);
        CHECK(account_store_begin(store_path, 0, &store) == -1 && errno == EPERM && !store);
        _exit(0);
    }
    int status;
    CHECK(waitpid(ordinary, &status, 0) == ordinary && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(account_store_begin(store_path, 0, &store) == 0);
    snapshot(store, old_text);
    account_store_end(store);
    observed("ordinary-cannot-read-change-or-recover-protected-intent");
    printf("ACCOUNT_TRANSACTION_PASS observations=%u\n", observations);
    return 0;
}
