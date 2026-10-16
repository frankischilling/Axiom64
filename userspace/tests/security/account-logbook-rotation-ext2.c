// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/logbook_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_ROTATION_EXT2_FAIL line=%d errno=%d expression=%s\n",         \
                    __LINE__, errno, #expression);                                                 \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const char arm_marker[] = "AXIOM64_ROTATION_BLOCK_ARM_V1";
static const char end_marker[] = "AXIOM64_ROTATION_BLOCK_END_V1";

static void bytes(int fd, void* data, size_t length, int writing) {
    for (size_t done = 0; done < length;) {
        ssize_t count = writing ? write(fd, (char*)data + done, length - done)
                                : read(fd, (char*)data + done, length - done);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count > 0);
        done += (size_t)count;
    }
}

static void child(pid_t* pid, int* finish, uid_t uid) {
    int ready[2], control[2];
    CHECK(pipe(ready) == 0 && pipe(control) == 0);
    *pid = fork();
    CHECK(*pid >= 0);
    if (!*pid) {
        close(ready[0]);
        close(control[1]);
        CHECK(ready[1] < 256 && control[0] < 256);
        // The observer forks a second shell while the first lease is held.
        // Shells must inherit neither privileged book locks nor other controls.
        for (int fd = 3; fd < 256; fd++)
            if (fd != ready[1] && fd != control[0])
                close(fd);
        CHECK(setsid() == getpid() && setgroups(0, NULL) == 0 &&
              setresgid(80000, 80000, 80000) == 0 && setresuid(uid, uid, uid) == 0);
        char value = 'x';
        bytes(ready[1], &value, 1, 1);
        _exit(read(control[0], &value, 1) < 0 ? 1 : 0);
    }
    close(ready[1]);
    close(control[0]);
    char value;
    bytes(ready[0], &value, 1, 0);
    CHECK(value == 'x' && close(ready[0]) == 0);
    *finish = control[1];
}

static void export_directory(const char* root, const char* relative, const char* phase,
                             unsigned depth) {
    CHECK(depth <= 1);
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s%s%s", root, *relative ? "/" : "", relative) <
          (int)sizeof(path));
    struct stat value;
    CHECK(lstat(path, &value) == 0 && S_ISDIR(value.st_mode) && (value.st_mode & 07777) == 0755 &&
          !value.st_uid && !value.st_gid);
    printf("ACCOUNT_ROTATION_EXT2_DIRECTORY phase=%s name=%s mode=0755 uid=0 gid=0\n", phase,
           *relative ? relative : ".");
    DIR* stream = opendir(path);
    CHECK(stream);
    unsigned entries = 0;
    struct dirent* entry;
    while ((entry = readdir(stream))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        CHECK(++entries <= 64);
        char name[128], filename[4096];
        CHECK(snprintf(name, sizeof(name), "%s%s%s", relative, *relative ? "/" : "",
                       entry->d_name) < (int)sizeof(name));
        CHECK(snprintf(filename, sizeof(filename), "%s/%s", root, name) < (int)sizeof(filename));
        CHECK(lstat(filename, &value) == 0 && !value.st_uid && !value.st_gid);
        if (S_ISDIR(value.st_mode)) {
            CHECK(!depth && !strncmp(entry->d_name, "archive-", 8));
            export_directory(root, name, phase, depth + 1);
            continue;
        }
        CHECK(S_ISREG(value.st_mode) && value.st_nlink == 1 && value.st_size <= 16384);
        printf("ACCOUNT_ROTATION_EXT2_FILE phase=%s name=%s mode=%04o uid=0 gid=0 links=1 "
               "bytes=%lld\n",
               phase, name, value.st_mode & 07777, (long long)value.st_size);
        int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        CHECK(fd >= 0);
        printf("ACCOUNT_ROTATION_EXT2_DATA phase=%s name=%s hex=", phase, name);
        unsigned char buffer[512];
        ssize_t count;
        off_t total = 0;
        while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
            for (ssize_t i = 0; i < count; i++)
                printf("%02x", buffer[i]);
            total += count;
        }
        CHECK(count == 0 && total == value.st_size && close(fd) == 0);
        putchar('\n');
    }
    CHECK(closedir(stream) == 0);
    CHECK(fflush(stdout) == 0);
}

static void utmp(const char* directory, unsigned expected) {
    char filename[4096];
    CHECK(snprintf(filename, sizeof(filename), "%s/utmp", directory) < (int)sizeof(filename));
    int fd = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0);
    struct account_login_entry entry;
    unsigned users = 0;
    ssize_t count;
    while ((count = read(fd, &entry, sizeof(entry))) > 0) {
        CHECK(count == sizeof(entry));
        users += entry.type == 7;
    }
    CHECK(count == 0 && close(fd) == 0 && users == expected);
}

static unsigned trigger(const struct account_logbook* book) {
    unsigned count = 0;
    for (size_t i = book->state.carried; i < book->count; i++)
        count += book->frames[i].kind == ACCOUNT_LOGIN_SUDO && book->frames[i].status == 900;
    return count;
}

static void run(const char* directory, const char* control, int expiry) {
    CHECK(ACCOUNT_LOGIN_JOURNAL_LIMIT / sizeof(struct account_login_frame) == 8 &&
          ACCOUNT_LOGIN_JOURNAL_LIMIT % sizeof(struct account_login_frame) == 128);
    struct account_logbook* book = NULL;
    struct account_session_lease* leases[2] = {0};
    pid_t children[2];
    int finish[2];
    CHECK(account_logbook_open(directory, 1, &book) == 0);
    for (unsigned i = 0; i < 2; i++) {
        child(&children[i], &finish[i], 70000 + i);
        struct account_profile profile = {
            .name = i ? "second" : "first", .uid = 70000 + i, .gid = 80000};
        CHECK(account_logbook_begin(book, &profile, children[i], i ? "pts/2" : "pts/1",
                                    &leases[i]) == 0);
    }
    for (unsigned i = 0; i < (expiry ? 30u : 6u); i++)
        CHECK(account_logbook_audit(book, i % 2 ? ACCOUNT_LOGIN_DENIED : ACCOUNT_LOGIN_SUDO,
                                    "fixture", 70000, "rotation", "pts/3", 100 + i) == 0);
    CHECK(book->count == 8 && book->state.generation == (expiry ? 5u : 1u) &&
          account_logbook_active(book, 70000) == 1 && account_logbook_active(book, 70001) == 1);
    utmp(directory, 2);
    export_directory(directory, "", "before", 0);
    printf("ACCOUNT_ROTATION_EXT2_READY scenario=%s generation=%llu events=%llu\n",
           expiry ? "expiry" : "basic", (unsigned long long)book->state.generation,
           (unsigned long long)(book->state.previous_events + book->count - book->state.carried));
    CHECK(fflush(stdout) == 0);
    int fd = open(control, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0);
    unsigned char sentinel[512] = {0};
    memcpy(sentinel, arm_marker, sizeof(arm_marker) - 1);
    bytes(fd, sentinel, sizeof(sentinel), 1);
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    int result =
        account_logbook_audit(book, ACCOUNT_LOGIN_SUDO, "fixture", 70000, "rotation", "pts/3", 900);
    int error = result < 0 ? errno : 0;
    fd = open(control, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0);
    memset(sentinel, 0, sizeof(sentinel));
    memcpy(sentinel, end_marker, sizeof(end_marker) - 1);
    bytes(fd, sentinel, sizeof(sentinel), 1);
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    printf("ACCOUNT_ROTATION_EXT2_ATTEMPT result=%d errno=%d\n", result, error);
    CHECK(fflush(stdout) == 0 && (result == 0 || (result == -1 && error == EIO)));
    account_logbook_close(book);
    book = NULL;
    CHECK(account_logbook_open(directory, 0, &book) == 0 && trigger(book) <= 1 &&
          account_logbook_active(book, 70000) == 1 && account_logbook_active(book, 70001) == 1);
    utmp(directory, 2);
    export_directory(directory, "", "retry", 0);
    printf("ACCOUNT_ROTATION_EXT2_PASS phase=run scenario=%s trigger=%u events=%llu live=2\n",
           expiry ? "expiry" : "basic", trigger(book),
           (unsigned long long)(book->state.previous_events + book->count - book->state.carried));
    CHECK(fflush(stdout) == 0);
    account_logbook_close(book);
    // Do not manufacture ENDs.  The fresh kernel must recover both lost holders.
    for (unsigned i = 0; i < 2; i++) {
        CHECK(close(finish[i]) == 0);
        int status;
        CHECK(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) &&
              !WEXITSTATUS(status));
    }
}

static void recover(const char* directory) {
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(directory, 0, &book) == 0 &&
          account_logbook_active(book, 70000) == 0 && account_logbook_active(book, 70001) == 0);
    unsigned recovered = 0;
    for (size_t i = book->state.carried; i < book->count; i++)
        recovered += book->frames[i].kind == ACCOUNT_LOGIN_RECOVERED;
    CHECK(recovered == 2 && trigger(book) <= 1);
    utmp(directory, 0);
    export_directory(directory, "", "recover", 0);
    printf("ACCOUNT_ROTATION_EXT2_PASS phase=recover trigger=%u events=%llu recovered=2 live=0\n",
           trigger(book),
           (unsigned long long)(book->state.previous_events + book->count - book->state.carried));
    CHECK(fflush(stdout) == 0);
    account_logbook_close(book);
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    export_directory(directory, "", "idempotent", 0);
    account_logbook_close(book);
}

int main(int argc, char** argv) {
    CHECK(!getuid() && !geteuid() && !getgid() && !getegid());
    CHECK((argc == 5 && !strcmp(argv[1], "run")) || (argc == 3 && !strcmp(argv[1], "recover")));
    if (!strcmp(argv[1], "run")) {
        CHECK(!strcmp(argv[4], "basic") || !strcmp(argv[4], "expiry"));
        run(argv[2], argv[3], !strcmp(argv[4], "expiry"));
    } else
        recover(argv[2]);
    return 0;
}
