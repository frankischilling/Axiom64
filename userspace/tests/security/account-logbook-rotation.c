// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/logbook_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_ROTATION_FAIL line=%d errno=%d expression=%s\n", __LINE__,    \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned injection, operation, mode, armed, partial_pending;
ssize_t __real_write(int, const void*, size_t);

static void report(const char* operation_name, int injected) {
    char line[160];
    int size =
        injected ? snprintf(line, sizeof(line),
                            "ACCOUNT_ROTATION_INJECTED mode=%u phase=%u operation=%s\n", mode,
                            operation, operation_name)
                 : snprintf(line, sizeof(line), "ACCOUNT_ROTATION_BOUNDARY phase=%u operation=%s\n",
                            operation, operation_name);
    if (size <= 0 || size >= (int)sizeof(line) || __real_write(2, line, (size_t)size) != size)
        _exit(78);
}

static int before(const char* operation_name) {
    if (!armed)
        return 0;
    operation++;
    if (!mode)
        report(operation_name, 0);
    if (partial_pending) {
        partial_pending = 0;
        errno = ENOSPC;
        return -1;
    }
    if (operation != injection)
        return 0;
    if (mode != 2)
        report(operation_name, 1);
    if (mode == 1)
        _exit(77);
    if (mode == 3 || mode == 4) {
        errno = mode == 3 ? EIO : ENOSPC;
        return -1;
    }
    if (mode >= 5 && strcmp(operation_name, "write") && strcmp(operation_name, "pwrite"))
        _exit(78);
    return 0;
}

static void after(const char* operation_name) {
    if (armed && operation == injection && mode == 2) {
        report(operation_name, 1);
        _exit(77);
    }
}

static void partial(ssize_t actual, size_t expected) {
    if (actual <= 0 || (size_t)actual >= expected)
        _exit(78);
    char line[160];
    int size = snprintf(line, sizeof(line),
                        "ACCOUNT_ROTATION_PARTIAL mode=%u phase=%u actual=%zd expected=%zu\n", mode,
                        operation, actual, expected);
    if (size <= 0 || size >= (int)sizeof(line) || __real_write(2, line, (size_t)size) != size)
        _exit(78);
    if (mode == 6)
        _exit(77);
    if (mode == 7)
        partial_pending = 1;
}

int __real_fsync(int);

int __wrap_fsync(int fd) {
    if (before("fsync") < 0)
        return -1;
    int result = __real_fsync(fd);
    after("fsync");
    return result;
}

int __real_renameat(int, const char*, int, const char*);

int __wrap_renameat(int first, const char* source, int second, const char* destination) {
    if (before("renameat") < 0)
        return -1;
    int result = __real_renameat(first, source, second, destination);
    after("renameat");
    return result;
}

int __real_unlinkat(int, const char*, int);

int __wrap_unlinkat(int directory, const char* name, int flags) {
    if (before("unlinkat") < 0)
        return -1;
    int result = __real_unlinkat(directory, name, flags);
    after("unlinkat");
    return result;
}

ssize_t __wrap_write(int fd, const void* bytes, size_t count) {
    if (before("write") < 0)
        return -1;
    if (armed && operation == injection && mode >= 5) {
        ssize_t result = __real_write(fd, bytes, count / 2);
        partial(result, count);
        return result;
    }
    ssize_t result = __real_write(fd, bytes, count);
    after("write");
    return result;
}

ssize_t __real_pwrite(int, const void*, size_t, off_t);

ssize_t __wrap_pwrite(int fd, const void* bytes, size_t count, off_t offset) {
    if (before("pwrite") < 0)
        return -1;
    if (armed && operation == injection && mode >= 5) {
        ssize_t result = __real_pwrite(fd, bytes, count / 2, offset);
        partial(result, count);
        return result;
    }
    ssize_t result = __real_pwrite(fd, bytes, count, offset);
    after("pwrite");
    return result;
}

static void path(char output[4096], const char* parent, const char* name) {
    CHECK(snprintf(output, 4096, "%s/%s", parent, name) < 4096);
}

static void child_start(pid_t* pid, int* finish) {
    int ready[2], control[2];
    CHECK(pipe(ready) == 0 && pipe(control) == 0);
    *pid = fork();
    CHECK(*pid >= 0);
    if (!*pid) {
        close(ready[0]);
        close(control[1]);
        CHECK(setsid() == getpid());
        CHECK(setgroups(0, NULL) == 0 && setresgid(1000, 1000, 1000) == 0 &&
              setresuid(1000, 1000, 1000) == 0);
        CHECK(write(ready[1], "x", 1) == 1);
        char value;
        _exit(read(control[0], &value, 1) == 1 ? 0 : 1);
    }
    close(ready[1]);
    close(control[0]);
    char value;
    CHECK(read(ready[0], &value, 1) == 1);
    close(ready[0]);
    *finish = control[1];
}

static void child_finish(pid_t pid, int finish) {
    CHECK(write(finish, "x", 1) == 1 && close(finish) == 0);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static struct account_logbook_state state(const char* directory) {
    char file[4096];
    path(file, directory, "state");
    struct account_logbook_state value = {.generation = 1};
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        CHECK(errno == ENOENT);
        return value;
    }
    CHECK(read(fd, &value, sizeof(value)) == sizeof(value) && close(fd) == 0);
    return value;
}

static unsigned events_file(const char* directory, uint64_t carried, unsigned wanted, int status) {
    char file[4096];
    path(file, directory, "journal");
    int fd = open(file, O_RDONLY);
    CHECK(fd >= 0);
    unsigned count = 0;
    struct account_login_frame frame;
    size_t index = 0;
    ssize_t size;
    while ((size = read(fd, &frame, sizeof(frame))) > 0) {
        CHECK(size == sizeof(frame) && account_login_frame_valid(&frame, index + 1));
        count += index >= carried && frame.kind == wanted && (status < 0 || frame.status == status);
        index++;
    }
    CHECK(size == 0 && close(fd) == 0 && index >= carried);
    return count;
}

static unsigned events(const char* directory, unsigned wanted, int status) {
    struct account_logbook_state current = state(directory);
    unsigned count = events_file(directory, current.carried, wanted, status);
    uint64_t first = current.generation > ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         ? current.generation - ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         : 1;
    for (uint64_t generation = first; generation < current.generation; generation++) {
        char name[25], archive[4096];
        snprintf(name, sizeof(name), "archive-%016llx", (unsigned long long)generation);
        path(archive, directory, name);
        struct account_logbook_state saved = state(archive);
        CHECK(saved.generation == generation);
        count += events_file(archive, saved.carried, wanted, status);
    }
    return count;
}

static void utmp_live(const char* directory, pid_t first, pid_t second) {
    char file[4096];
    path(file, directory, "utmp");
    int fd = open(file, O_RDONLY);
    CHECK(fd >= 0);
    struct account_login_entry entries[2];
    CHECK(read(fd, entries, sizeof(entries)) == sizeof(entries));
    char extra;
    CHECK(read(fd, &extra, 1) == 0 && close(fd) == 0);
    CHECK(entries[0].type == 7 && entries[1].type == 7 && entries[0].pid == first &&
          entries[1].pid == second);
}

static enum account_login_kind audit_kind(int status) {
    return status & 1 ? ACCOUNT_LOGIN_DENIED : ACCOUNT_LOGIN_SUDO;
}

static void audit(struct account_logbook* book, int status) {
    CHECK(account_logbook_audit(book, audit_kind(status), "alice", 1000, "root", "/dev/tty",
                                status) == 0);
}

static void damaged_byte(const char* directory, const char* file) {
    char name[4096];
    path(name, directory, file);
    int fd = open(name, O_RDWR);
    unsigned char original, damaged;
    CHECK(fd >= 0 && pread(fd, &original, 1, 0) == 1);
    damaged = original ^ 1;
    CHECK(pwrite(fd, &damaged, 1, 0) == 1 && fsync(fd) == 0);
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EUCLEAN);
    CHECK(pwrite(fd, &original, 1, 0) == 1 && fsync(fd) == 0 && close(fd) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    account_logbook_close(book);
}

static void metadata(const char* directory) {
    char file[4096], saved[4096];
    path(file, directory, "state");
    path(saved, directory, "saved-state");
    struct account_logbook* book = NULL;
    CHECK(chmod(file, 0644) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EACCES);
    CHECK(chmod(file, 0600) == 0 && link(file, saved) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EACCES);
    CHECK(unlink(saved) == 0 && rename(file, saved) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EUCLEAN);
    CHECK(symlink("journal", file) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == ELOOP);
    CHECK(unlink(file) == 0 && rename(saved, file) == 0);
    damaged_byte(directory, "state");
    damaged_byte(directory, "archive-0000000000000001/journal");
    damaged_byte(directory, "archive-0000000000000001/wtmp");
    damaged_byte(directory, "archive-0000000000000001/btmp");
    damaged_byte(directory, "archive-0000000000000001/auth.log");
    path(file, directory, "rotation");
    int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    unsigned char invalid[112] = {0};
    CHECK(fd >= 0 && write(fd, invalid, sizeof(invalid)) == sizeof(invalid) && fsync(fd) == 0 &&
          close(fd) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EUCLEAN);
    CHECK(unlink(file) == 0);
    path(file, directory, "archive-ffffffffffffffff");
    CHECK(mkdir(file, 0755) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EUCLEAN);
    CHECK(rmdir(file) == 0 && account_logbook_open(directory, 0, &book) == 0);
    account_logbook_close(book);
}

static void live_limit(const char* directory) {
    CHECK(ACCOUNT_LOGIN_LIVE_LIMIT == 4);
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(directory, 1, &book) == 0);
    account_logbook_close(book);
    pid_t children[5];
    int finish[5];
    for (unsigned i = 0; i < 5; i++)
        child_start(&children[i], &finish[i]);
    struct account_session_lease* leases[4];
    struct account_profile profile = {.name = "alice", .uid = 1000, .gid = 1000};
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    for (unsigned i = 0; i < 4; i++) {
        char terminal[32];
        snprintf(terminal, sizeof(terminal), "/dev/pts/%u", i + 1);
        CHECK(account_logbook_begin(book, &profile, children[i], terminal, &leases[i]) == 0);
    }
    struct account_session_lease* rejected = NULL;
    CHECK(account_logbook_begin(book, &profile, children[4], "/dev/pts/5", &rejected) == -1 &&
          errno == ENOSPC && !rejected);
    account_logbook_close(book);
    CHECK(account_logbook_open(directory, 0, &book) == 0 &&
          account_logbook_active(book, 1000) == 1);
    account_logbook_close(book);
    for (unsigned i = 0; i < 5; i++)
        child_finish(children[i], finish[i]);
    for (unsigned i = 0; i < 4; i++)
        CHECK(account_logbook_end(leases[i], 0) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == 0 &&
          account_logbook_active(book, 1000) == 0);
    account_logbook_close(book);
    CHECK(events(directory, ACCOUNT_LOGIN_START, -1) == 4 &&
          events(directory, ACCOUNT_LOGIN_END, -1) == 4);
}

int main(int argc, char** argv) {
    CHECK(argc == 5 && !geteuid() && !getegid());
    const char* directory = argv[1];
    int cyclic = !strcmp(argv[2], "cyclic");
    mode = (unsigned)strtoul(argv[3], NULL, 10);
    injection = (unsigned)strtoul(argv[4], NULL, 10);
    CHECK(mode <= 7 && ACCOUNT_LOGIN_JOURNAL_LIMIT / sizeof(struct account_login_frame) == 8);
    if (!strcmp(argv[2], "open-reject")) {
        struct account_logbook* rejected = NULL;
        CHECK(account_logbook_open(directory, 0, &rejected) == -1 && errno == (int)injection);
        printf("ACCOUNT_ROTATION_PASS scenario=open-reject mode=0 phase=%u\n", injection);
        return 0;
    }
    if (!strcmp(argv[2], "live-limit")) {
        live_limit(directory);
        puts("ACCOUNT_ROTATION_PASS scenario=live-limit mode=0 phase=0");
        return 0;
    }
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(directory, 1, &book) == 0);
    account_logbook_close(book);
    pid_t children[2];
    int finish[2];
    child_start(&children[0], &finish[0]);
    child_start(&children[1], &finish[1]);
    struct account_profile profile = {.name = "alice", .uid = 1000, .gid = 1000};
    struct account_session_lease* leases[2];
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    CHECK(account_logbook_begin(book, &profile, children[0], "/dev/pts/1", &leases[0]) == 0);
    CHECK(account_logbook_begin(book, &profile, children[1], "/dev/pts/2", &leases[1]) == 0);
    for (int i = 0; i < 6; i++)
        audit(book, i);
    account_logbook_close(book);
    int expiry = !strcmp(argv[2], "expiry");
    if (expiry) {
        CHECK(account_logbook_open(directory, 0, &book) == 0);
        for (int i = 100; i < 124; i++)
            audit(book, i);
        account_logbook_close(book);
        CHECK(state(directory).generation == 5);
    }
    if (cyclic) {
        for (int i = 100; i < 180; i++) {
            CHECK(account_logbook_open(directory, 0, &book) == 0);
            audit(book, i);
            CHECK(account_logbook_active(book, 1000) == 1);
            account_logbook_close(book);
            utmp_live(directory, children[0], children[1]);
        }
        struct account_logbook_state current = state(directory);
        CHECK(current.generation == 15 && current.carried == 2);
        for (int i = 100; i < 180; i++)
            CHECK(events(directory, audit_kind(i), i) == (i >= 154 ? 1u : 0u));
        CHECK(events(directory, ACCOUNT_LOGIN_START, -1) == 0);
        DIR* stream = opendir(directory);
        CHECK(stream);
        unsigned archives = 0;
        struct dirent* entry;
        while ((entry = readdir(stream)))
            archives += !strncmp(entry->d_name, "archive-", 8);
        CHECK(closedir(stream) == 0 && archives == ACCOUNT_LOGIN_ARCHIVE_LIMIT);
    } else {
        pid_t rotator = fork();
        CHECK(rotator >= 0);
        if (!rotator) {
            CHECK(account_logbook_open(directory, 0, &book) == 0);
            armed = 1;
            int result =
                account_logbook_audit(book, audit_kind(9), "alice", 1000, "root", "/dev/tty", 9);
            armed = 0;
            if (!mode)
                printf("ACCOUNT_ROTATION_PHASES %u\n", operation);
            CHECK((mode == 0 || mode == 5) ? result == 0 : result == -1);
            CHECK(!mode || operation >= injection);
            account_logbook_close(book);
            exit(0);
        }
        int result;
        CHECK(waitpid(rotator, &result, 0) == rotator && WIFEXITED(result));
        CHECK(WEXITSTATUS(result) == (mode == 1 || mode == 2 || mode == 6 ? 77 : 0));
        CHECK(account_logbook_open(directory, 0, &book) == 0);
        CHECK(account_logbook_active(book, 1000) == 1);
        utmp_live(directory, children[0], children[1]);
        for (int i = expiry ? 100 : 0; i < (expiry ? 124 : 6); i++)
            CHECK(events(directory, audit_kind(i), i) == 1);
        CHECK(events(directory, ACCOUNT_LOGIN_START, -1) <= 2);
        CHECK(events(directory, audit_kind(9), 9) <= 1);
        if (!events(directory, audit_kind(9), 9))
            audit(book, 9);
        account_logbook_close(book);
        CHECK(events(directory, audit_kind(9), 9) == 1);
        CHECK(events(directory, ACCOUNT_LOGIN_START, -1) == (expiry ? 0 : 2));
    }
    child_finish(children[0], finish[0]);
    child_finish(children[1], finish[1]);
    CHECK(account_logbook_end(leases[0], 0) == 0 && account_logbook_end(leases[1], 0) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == 0 &&
          account_logbook_active(book, 1000) == 0);
    if (cyclic)
        CHECK(book->state.previous_events + book->count - book->state.carried == 90);
    account_logbook_close(book);
    CHECK(events(directory, ACCOUNT_LOGIN_END, -1) == 2);
    if (!strcmp(argv[2], "metadata"))
        metadata(directory);
    struct account_logbook_state current = state(directory);
    uint64_t first = current.generation > ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         ? current.generation - ACCOUNT_LOGIN_ARCHIVE_LIMIT
                         : 1;
    pid_t ordinary = fork();
    CHECK(ordinary >= 0);
    if (!ordinary) {
        CHECK(setgroups(0, NULL) == 0 && setresgid(1001, 1001, 1001) == 0 &&
              setresuid(1001, 1001, 1001) == 0);
        CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EPERM);
        char file[4096];
        path(file, directory, "state");
        CHECK(open(file, O_RDONLY) == -1 && errno == EACCES);
        path(file, directory, "journal");
        CHECK(open(file, O_RDONLY) == -1 && errno == EACCES);
        char name[64];
        snprintf(name, sizeof(name), "archive-%016llx/journal", (unsigned long long)first);
        path(file, directory, name);
        CHECK(open(file, O_RDONLY) == -1 && errno == EACCES);
        snprintf(name, sizeof(name), "archive-%016llx/auth.log", (unsigned long long)first);
        path(file, directory, name);
        CHECK(open(file, O_RDONLY) == -1 && errno == EACCES);
        snprintf(name, sizeof(name), "archive-%016llx/wtmp", (unsigned long long)first);
        path(file, directory, name);
        int public_record = open(file, O_RDONLY);
        CHECK(public_record >= 0 && close(public_record) == 0);
        _exit(0);
    }
    int status;
    CHECK(waitpid(ordinary, &status, 0) == ordinary && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);
    printf("ACCOUNT_ROTATION_PASS scenario=%s mode=%u phase=%u\n", argv[2], mode, injection);
    return 0;
}
