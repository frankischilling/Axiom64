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
            fprintf(stderr, "ACCOUNT_ROTATION_GUEST_FAIL line=%d errno=%d expression=%s\n",        \
                    __LINE__, errno, #expression);                                                 \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const uid_t fixture_uid = 70000;
static const gid_t fixture_gid = 80000;

static void path(char output[4096], const char* parent, const char* name) {
    CHECK(snprintf(output, 4096, "%s/%s", parent, name) < 4096);
}

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

static void child_start(pid_t* pid, int* finish) {
    int ready[2], control[2];
    CHECK(pipe(ready) == 0 && pipe(control) == 0);
    *pid = fork();
    CHECK(*pid >= 0);
    if (!*pid) {
        close(ready[0]);
        close(control[1]);
        CHECK(setsid() == getpid() && setgroups(0, NULL) == 0);
        CHECK(setresgid(fixture_gid, fixture_gid, fixture_gid) == 0 &&
              setresuid(fixture_uid, fixture_uid, fixture_uid) == 0);
        CHECK(getuid() == fixture_uid && geteuid() == fixture_uid && getgid() == fixture_gid &&
              getegid() == fixture_gid);
        char value = 'x';
        bytes(ready[1], &value, 1, 1);
        // EOF also ends the owned observer child after the supervisor exits.
        _exit(read(control[0], &value, 1) < 0 ? 1 : 0);
    }
    close(ready[1]);
    close(control[0]);
    char value;
    bytes(ready[0], &value, 1, 0);
    CHECK(value == 'x' && close(ready[0]) == 0);
    *finish = control[1];
}

static void child_finish(pid_t pid, int finish) {
    char value = 'x';
    bytes(finish, &value, 1, 1);
    CHECK(close(finish) == 0);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
}

static struct account_logbook_state state(const char* directory) {
    char name[4096];
    path(name, directory, "state");
    int fd = open(name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct account_logbook_state result;
    CHECK(fd >= 0);
    bytes(fd, &result, sizeof(result), 0);
    char extra;
    CHECK(read(fd, &extra, 1) == 0 && close(fd) == 0);
    return result;
}

static void file(const char* directory, const char* relative, mode_t mode, const char* phase) {
    char name[4096];
    path(name, directory, relative);
    struct stat value;
    CHECK(lstat(name, &value) == 0 && S_ISREG(value.st_mode) && (value.st_mode & 07777) == mode &&
          !value.st_uid && !value.st_gid && value.st_nlink == 1);
    printf(
        "ACCOUNT_ROTATION_GUEST_FILE phase=%s name=%s mode=%04o uid=%u gid=%u links=1 bytes=%lld\n",
        phase, relative, mode, value.st_uid, value.st_gid, (long long)value.st_size);
    int fd = open(name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0);
    printf("ACCOUNT_ROTATION_GUEST_DATA phase=%s name=%s hex=", phase, relative);
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

static unsigned metadata(const char* directory, const char* phase) {
    struct stat value;
    CHECK(lstat(directory, &value) == 0 && S_ISDIR(value.st_mode) &&
          (value.st_mode & 07777) == 0755 && !value.st_uid && !value.st_gid);
    const char* names[] = {"lock", "journal", "state", "utmp", "wtmp", "btmp", "auth.log"};
    for (unsigned i = 0; i < 7; i++)
        file(directory, names[i], i == 3 || i == 4 ? 0644 : 0600, phase);
    DIR* stream = opendir(directory);
    CHECK(stream);
    unsigned archives = 0, leases = 0;
    struct dirent* entry;
    while ((entry = readdir(stream))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (!strncmp(entry->d_name, "archive-", 8)) {
            CHECK(strlen(entry->d_name) == 24);
            unsigned long long generation = strtoull(entry->d_name + 8, NULL, 16);
            CHECK(generation >= 6 && generation <= 9);
            char archive[4096];
            path(archive, directory, entry->d_name);
            CHECK(lstat(archive, &value) == 0 && S_ISDIR(value.st_mode) &&
                  (value.st_mode & 07777) == 0755 && !value.st_uid && !value.st_gid);
            const char* archive_files[] = {"journal", "state", "wtmp", "btmp", "auth.log"};
            for (unsigned i = 0; i < 5; i++) {
                char relative[96];
                snprintf(relative, sizeof(relative), "%s/%s", entry->d_name, archive_files[i]);
                file(directory, relative, i == 2 ? 0644 : 0600, phase);
            }
            struct account_logbook_state saved = state(archive);
            CHECK(saved.generation == generation && saved.carried == 2);
            archives++;
        } else if (!strncmp(entry->d_name, "l-", 2)) {
            CHECK(strlen(entry->d_name) == 34);
            for (unsigned i = 2; i < 34; i++)
                CHECK(strchr("0123456789abcdef", entry->d_name[i]));
            file(directory, entry->d_name, 0600, phase);
            leases++;
        } else {
            unsigned i;
            for (i = 0; i < 7 && strcmp(entry->d_name, names[i]); i++)
                ;
            CHECK(i < 7);
        }
    }
    CHECK(closedir(stream) == 0 && archives == ACCOUNT_LOGIN_ARCHIVE_LIMIT);
    return leases;
}

static void access_control(const char* directory) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgroups(0, NULL) == 0 && setresgid(80001, 80001, 80001) == 0 &&
              setresuid(70001, 70001, 70001) == 0);
        struct account_logbook* denied = NULL;
        CHECK(account_logbook_open(directory, 0, &denied) == -1 && errno == EPERM && !denied);
        char name[4096];
        path(name, directory, "state");
        CHECK(open(name, O_RDONLY) == -1 && errno == EACCES);
        path(name, directory, "journal");
        CHECK(open(name, O_RDONLY) == -1 && errno == EACCES);
        path(name, directory, "utmp");
        int fd = open(name, O_RDONLY);
        CHECK(fd >= 0 && close(fd) == 0);
        path(name, directory, "archive-0000000000000009/wtmp");
        fd = open(name, O_RDONLY);
        CHECK(fd >= 0 && close(fd) == 0);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
}

static void damaged_metadata(const char* directory) {
    char name[4096], extra[4096];
    path(name, directory, "state");
    struct account_logbook* book = NULL;
    CHECK(chmod(name, 0644) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EACCES && !book);
    CHECK(chmod(name, 0600) == 0 && chown(name, 70001, 80001) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EACCES && !book);
    CHECK(chown(name, 0, 0) == 0);
    path(extra, directory, "extra-state");
    CHECK(link(name, extra) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EACCES && !book);
    CHECK(unlink(extra) == 0 && account_logbook_open(directory, 0, &book) == 0);
    account_logbook_close(book);
}

static void audit(struct account_logbook* book, unsigned index) {
    CHECK(account_logbook_audit(book, index & 1 ? ACCOUNT_LOGIN_DENIED : ACCOUNT_LOGIN_SUDO,
                                index & 1 ? "missing" : "alice",
                                index & 1 ? (uid_t)-1 : fixture_uid, index & 1 ? NULL : "root",
                                "/dev/tty", (int)index) == 0);
}

static void verify_current(const char* directory, int recovered) {
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    CHECK(book->state.generation == 10 && book->state.carried == 1 &&
          book->state.previous_events == 56 && book->count == (size_t)(recovered ? 3 : 2));
    CHECK(book->frames[0].kind == ACCOUNT_LOGIN_START && book->frames[0].uid == fixture_uid &&
          book->frames[0].gid == fixture_gid && !strcmp(book->frames[0].entry.user, "alice"));
    CHECK(book->frames[1].kind == ACCOUNT_LOGIN_DENIED && book->frames[1].status == 53);
    if (recovered)
        CHECK(book->frames[2].kind == ACCOUNT_LOGIN_RECOVERED &&
              book->frames[2].uid == fixture_uid && book->frames[2].gid == fixture_gid &&
              !memcmp(book->frames[0].token, book->frames[2].token, 16));
    CHECK(account_logbook_active(book, fixture_uid) == !recovered);
    printf("ACCOUNT_ROTATION_GUEST_STATE phase=%s generation=10 carried=1 previous_events=56 "
           "frames=%zu uid=%u gid=%u active=%d\n",
           recovered ? "recover" : "prepare", book->count, book->frames[0].uid, book->frames[0].gid,
           !recovered);
    account_logbook_close(book);
    char name[4096];
    path(name, directory, "utmp");
    int fd = open(name, O_RDONLY);
    struct account_login_entry entry;
    CHECK(fd >= 0);
    bytes(fd, &entry, sizeof(entry), 0);
    char extra;
    CHECK(read(fd, &extra, 1) == 0 && close(fd) == 0 && entry.type == (recovered ? 8 : 7));
    CHECK(recovered ? !entry.user[0] : !strcmp(entry.user, "alice"));
    CHECK(metadata(directory, recovered ? "recover" : "prepare") == (unsigned)!recovered);
    access_control(directory);
}

static void prepare(const char* directory) {
    CHECK(ACCOUNT_LOGIN_JOURNAL_LIMIT == 3584 && ACCOUNT_LOGIN_LIVE_LIMIT == 4);
    pid_t children[2];
    int finish[2];
    child_start(&children[0], &finish[0]);
    child_start(&children[1], &finish[1]);
    struct account_profile profile = {.name = "alice", .uid = 70000, .gid = 80000};
    struct account_logbook* book = NULL;
    struct account_session_lease* leases[2];
    CHECK(account_logbook_open(directory, 1, &book) == 0);
    CHECK(account_logbook_begin(book, &profile, children[0], "/dev/pts/1", &leases[0]) == 0 &&
          account_logbook_begin(book, &profile, children[1], "/dev/pts/2", &leases[1]) == 0);
    for (unsigned i = 0; i < 48; i++) {
        audit(book, i);
        CHECK(account_logbook_active(book, fixture_uid) == 1);
    }
    CHECK(account_logbook_audit(book, ACCOUNT_LOGIN_BOOT, "", 0, NULL, NULL, 0) == -1 &&
          errno == EBUSY);
    account_logbook_close(book);
    child_finish(children[0], finish[0]);
    CHECK(account_logbook_end(leases[0], 0) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    for (unsigned i = 48; i < 54; i++)
        audit(book, i);
    account_logbook_close(book);
    damaged_metadata(directory);
    verify_current(directory, 0);
    // Deliberately omit END for the surviving lease. Process exit releases its
    // lock; the persisted record is reconciled by the fresh observer/kernel.
    (void)leases[1];
    (void)finish[1];
    puts("ACCOUNT_ROTATION_GUEST_PASS phase=prepare policy=small generation=10 archives=4");
}

static uint32_t file_crc(int fd) {
    unsigned char buffer[16384];
    uint32_t crc = UINT32_MAX;
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) > 0)
        for (ssize_t i = 0; i < count; i++) {
            crc ^= buffer[i];
            for (unsigned bit = 0; bit < 8; bit++)
                crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
        }
    CHECK(count == 0);
    return crc ^ UINT32_MAX;
}

static void production_limit(const char* directory) {
    CHECK(ACCOUNT_LOGIN_JOURNAL_LIMIT == 32u * 1024 * 1024 && ACCOUNT_LOGIN_LIVE_LIMIT == 1024);
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(directory, 1, &book) == 0);
    account_logbook_close(book);
    char name[4096];
    path(name, directory, "journal");
    int fd = open(name, O_WRONLY | O_TRUNC | O_NOFOLLOW);
    CHECK(fd >= 0);
    struct account_login_frame base, frames[64];
    CHECK(account_login_frame_make(&base, ACCOUNT_LOGIN_SUDO, "alice", fixture_uid, 0, getpid(),
                                   "/dev/tty", "root", 0, NULL) == 0);
    size_t capacity = ACCOUNT_LOGIN_JOURNAL_LIMIT / sizeof(base);
    for (size_t done = 0; done < capacity;) {
        size_t count = capacity - done < 64 ? capacity - done : 64;
        for (size_t i = 0; i < count; i++) {
            frames[i] = base;
            account_login_frame_seal(&frames[i], done + i + 1);
        }
        bytes(fd, frames, count * sizeof(base), 1);
        done += count;
    }
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    account_login_frame_seal(&base, 1);
    printf("ACCOUNT_ROTATION_GUEST_DEFAULT_BASE ");
    for (size_t i = 0; i < sizeof(base); i++)
        printf("%02x", ((unsigned char*)&base)[i]);
    putchar('\n');
    fflush(stdout);
    CHECK(account_logbook_open(directory, 0, &book) == 0 && book->count == capacity &&
          book->state.generation == 1);
    CHECK(account_logbook_audit(book, ACCOUNT_LOGIN_SUDO, "alice", fixture_uid, "root", "/dev/tty",
                                65535) == 0);
    CHECK(book->state.generation == 2 && !book->state.carried &&
          book->state.previous_events == capacity && book->count == 1);
    account_logbook_close(book);
    path(name, directory, "archive-0000000000000001/journal");
    fd = open(name, O_RDONLY | O_NOFOLLOW);
    struct stat value;
    CHECK(fd >= 0 && fstat(fd, &value) == 0 && value.st_size == (off_t)(capacity * sizeof(base)));
    uint32_t crc = file_crc(fd);
    CHECK(close(fd) == 0);
    printf("ACCOUNT_ROTATION_GUEST_DEFAULT_ARCHIVE frames=%zu bytes=%zu crc32=%08x\n", capacity,
           capacity * sizeof(base), crc);
    puts("ACCOUNT_ROTATION_GUEST_PASS phase=default policy=33554432 generation=2 archives=1");
}

int main(int argc, char** argv) {
    CHECK(argc == 3 && !getuid() && !geteuid() && !getgid() && !getegid());
    if (!strcmp(argv[1], "prepare"))
        prepare(argv[2]);
    else if (!strcmp(argv[1], "recover")) {
        CHECK(ACCOUNT_LOGIN_JOURNAL_LIMIT == 3584 && ACCOUNT_LOGIN_LIVE_LIMIT == 4);
        verify_current(argv[2], 1);
        puts("ACCOUNT_ROTATION_GUEST_PASS phase=recover policy=small generation=10 archives=4");
    } else {
        CHECK(!strcmp(argv[1], "default"));
        production_limit(argv[2]);
    }
    fflush(stdout);
    return 0;
}
