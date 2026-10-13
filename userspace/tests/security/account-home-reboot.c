// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/home.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
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
            fprintf(stderr, "ACCOUNT_HOME_REBOOT_FAIL line=%d errno=%d\n", __LINE__, errno);       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const char* names[] = {"pending", "published", "nonempty",
                              "staged",  "unproven",  "replacement"};

struct claim {
    struct account_home_key key;
    uint64_t inode;
    uint32_t uid, gid, mode;
    char staged[40];
};

struct state {
    char magic[8], boot[40];
    struct claim claims[6];
};

_Static_assert(sizeof(struct claim) == 80 && sizeof(struct state) == 528, "fixture format");
static int directory, gate, stopping;
static char stage[40];

int __real_mkdirat(int, const char*, mode_t);
long __real_syscall(long, ...);
int __real_fsetxattr(int, const char*, const void*, size_t, int);

int __wrap_mkdirat(int parent, const char* name, mode_t mode) {
    if (!strncmp(name, ".home-", 6)) {
        CHECK(strlen(name) < sizeof(stage));
        memset(stage, 0, sizeof(stage));
        strcpy(stage, name);
    }
    return __real_mkdirat(parent, name, mode);
}

static void checkpoint(void) {
    CHECK(write(gate, stage, sizeof(stage)) == sizeof(stage));
    for (;;)
        pause();
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
    if (stopping == 1)
        checkpoint();
    return __real_syscall(number, from, source, to, target, flags);
}

int __wrap_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    if (stopping == 2) {
        CHECK(fsync(fd) == 0 && fsync(directory) == 0);
        checkpoint();
    }
    return __real_fsetxattr(fd, name, value, size, flags);
}

static void boot_id(char value[40]) {
    memset(value, 0, 40);
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    ssize_t size = read(fd, value, 39);
    CHECK((size == 36 || (size == 37 && value[36] == '\n')) && close(fd) == 0);
    value[36] = 0;
    for (unsigned i = 0; i < 36; i++)
        CHECK(i == 8 || i == 13 || i == 18 || i == 23
                  ? value[i] == '-'
                  : (value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'));
}

static struct stat metadata(const char* name) {
    struct stat value;
    CHECK(fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) == 0);
    return value;
}

static int absent(const char* name) {
    struct stat value;
    return fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}

static void pathname(char output[4096], const char* root, const char* name) {
    CHECK(snprintf(output, 4096, "%s/%s", root, name) < 4096);
}

static void save(const struct state* state) {
    int fd = openat(directory, "claims", O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    CHECK(fd >= 0 && fchmod(fd, 0600) == 0 && write(fd, state, sizeof(*state)) == sizeof(*state) &&
          fsync(fd) == 0 && close(fd) == 0 && fsync(directory) == 0);
}

static void data(const char* name, int create) {
    int parent = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(parent >= 0);
    int fd =
        openat(parent, "data", (create ? O_CREAT | O_EXCL | O_WRONLY : O_RDONLY) | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    char bytes[10] = {0};
    if (create)
        CHECK(write(fd, "preserved", 9) == 9 && fchown(fd, 1000, 1000) == 0 && fsync(fd) == 0);
    else
        CHECK(read(fd, bytes, sizeof(bytes)) == 9 && !strcmp(bytes, "preserved"));
    CHECK(close(fd) == 0 && fsync(parent) == 0 && close(parent) == 0);
}

static void prepare(const char* root) {
    struct state state = {.magic = "A64HOME1"};
    boot_id(state.boot);
    for (unsigned i = 0; i < 6; i++)
        CHECK(account_home_key_new(&state.claims[i].key) == 0);
    // This fixture persists keys before creation; it does not implement the
    // account database's pending-intent protocol.
    save(&state);
    for (unsigned i = 0; i < 6; i++) {
        struct claim* claim = &state.claims[i];
        char path[4096];
        pathname(path, root, names[i]);
        if (i == 3 || i == 4) {
            int pipes[2];
            CHECK(pipe(pipes) == 0);
            pid_t child = fork();
            CHECK(child >= 0);
            if (!child) {
                CHECK(close(pipes[0]) == 0);
                gate = pipes[1];
                stopping = i == 3 ? 1 : 2;
                struct account_home* home = NULL;
                account_home_create_key(path, 1000, 1000, &claim->key, &home);
                CHECK(0);
            }
            CHECK(close(pipes[1]) == 0 &&
                  read(pipes[0], claim->staged, sizeof(claim->staged)) == sizeof(claim->staged) &&
                  close(pipes[0]) == 0 && kill(child, SIGKILL) == 0);
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                  WTERMSIG(status) == SIGKILL && absent(names[i]));
        } else {
            struct account_home* home = NULL;
            CHECK(account_home_create_key(path, 1000, 1000, &claim->key, &home) == 0 &&
                  account_home_finish(home, 1) == 0);
            if (i == 1 || i == 2)
                data(names[i], 1);
            if (i == 5) {
                CHECK(unlinkat(directory, names[i], AT_REMOVEDIR) == 0 &&
                      mkdirat(directory, names[i], 0700) == 0);
                int fd = openat(directory, names[i], O_RDONLY | O_DIRECTORY);
                CHECK(fd >= 0 && fchown(fd, 1000, 1000) == 0 && fsync(fd) == 0 && close(fd) == 0);
            }
        }
        struct stat value = metadata(*claim->staged ? claim->staged : names[i]);
        claim->inode = value.st_ino;
        claim->uid = value.st_uid;
        claim->gid = value.st_gid;
        claim->mode = value.st_mode;
    }
    save(&state);
    puts("ACCOUNT_HOME_REBOOT_PREPARED cases=6");
}

static void identity(const char* name, const struct claim* claim) {
    struct stat value = metadata(name);
    CHECK(value.st_ino == claim->inode && value.st_uid == claim->uid &&
          value.st_gid == claim->gid && value.st_mode == claim->mode);
}

static void verify(const char* root) {
    struct state state;
    int fd = openat(directory, "claims", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat value;
    CHECK(fd >= 0 && fstat(fd, &value) == 0 && S_ISREG(value.st_mode) && !value.st_uid &&
          !value.st_gid && (value.st_mode & 07777) == 0600 && value.st_nlink == 1 &&
          value.st_size == sizeof(state) && read(fd, &state, sizeof(state)) == sizeof(state) &&
          close(fd) == 0 && !memcmp(state.magic, "A64HOME1", 8));
    char boot[40];
    boot_id(boot);
    CHECK(strcmp(boot, state.boot));
    puts("ACCOUNT_HOME_REBOOT_OBSERVATION case=new-kernel-boot");
    for (unsigned i = 0; i < 6; i++) {
        char path[4096];
        pathname(path, root, names[i]);
        const struct claim* claim = &state.claims[i];
        int result = account_home_recover(path, &claim->key, i == 1);
        if (i == 0 || i == 3) {
            CHECK(result == 0 && absent(names[i]) && (!*claim->staged || absent(claim->staged)));
        } else {
            CHECK(i == 1 ? result == 0 : result == -1 && errno == (i == 2 ? ENOTEMPTY : ESTALE));
            identity(*claim->staged ? claim->staged : names[i], claim);
            if (i == 1 || i == 2)
                data(names[i], 0);
        }
        printf("ACCOUNT_HOME_REBOOT_OBSERVATION case=%s\n", names[i]);
    }
    fd = openat(directory, "published", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(fd >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        unsigned char bytes[16];
        CHECK(fgetxattr(fd, "trusted.axiom64.home", bytes, sizeof(bytes)) == -1 &&
              errno == ENODATA);
        CHECK(fsetxattr(fd, "trusted.axiom64.home", bytes, sizeof(bytes), 0) == -1 &&
              errno == EPERM);
        CHECK(fremovexattr(fd, "trusted.axiom64.home") == -1 && errno == EPERM);
        CHECK(flistxattr(fd, (char*)bytes, sizeof(bytes)) == 0);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
          close(fd) == 0 && fsync(directory) == 0);
    puts("ACCOUNT_HOME_REBOOT_OBSERVATION case=ordinary-owner-denied");
    puts("ACCOUNT_HOME_REBOOT_PASS observations=8");
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    CHECK(argc == 3 && argv[2][0] == '/');
    int creating = !strcmp(argv[1], "create");
    CHECK(creating || !strcmp(argv[1], "verify"));
    if (creating)
        CHECK(mkdir(argv[2], 0755) == 0);
    directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(directory >= 0);
    (creating ? prepare : verify)(argv[2]);
    CHECK(close(directory) == 0);
    return 0;
}
