// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/logbook.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_LOGBOOK_FAIL line=%d errno=%d expression=%s\n", __LINE__,     \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;

static void observed(const char* name) {
    printf("ACCOUNT_LOGBOOK_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void path(char output[4096], const char* parent, const char* name) {
    CHECK(snprintf(output, 4096, "%s/%s", parent, name) < 4096);
}

static void reap(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void byte(int fd, int writing) {
    char value = 'x';
    CHECK((writing ? write(fd, &value, 1) : read(fd, &value, 1)) == 1 && value == 'x');
}

struct child {
    int master, slave, finish[2];
    pid_t pid;
    char terminal[64];
};

static void child_start(struct child* child) {
    child->master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(child->master >= 0 && grantpt(child->master) == 0 && unlockpt(child->master) == 0);
    CHECK(ptsname_r(child->master, child->terminal, sizeof(child->terminal)) == 0);
    child->slave = open(child->terminal, O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(child->slave >= 0 && fchown(child->slave, 1000, 1000) == 0 &&
          fchmod(child->slave, 0600) == 0);
    int ready[2];
    CHECK(pipe(ready) == 0 && pipe(child->finish) == 0);
    child->pid = fork();
    CHECK(child->pid >= 0);
    if (!child->pid) {
        close(child->master);
        close(ready[0]);
        close(child->finish[1]);
        CHECK(setsid() == getpid() && ioctl(child->slave, TIOCSCTTY, 0) == 0);
        CHECK(setgroups(0, NULL) == 0 && setresgid(1000, 1000, 1000) == 0 &&
              setresuid(1000, 1000, 1000) == 0);
        byte(ready[1], 1);
        byte(child->finish[0], 0);
        _exit(0);
    }
    close(ready[1]);
    close(child->finish[0]);
    byte(ready[0], 0);
    close(ready[0]);
}

static void child_finish(struct child* child) {
    byte(child->finish[1], 1);
    reap(child->pid);
    close(child->finish[1]);
    close(child->master);
    close(child->slave);
}

static struct account_login_entry entry(const char* directory) {
    char file[4096];
    path(file, directory, "utmp");
    int fd = open(file, O_RDONLY);
    struct account_login_entry result;
    CHECK(fd >= 0 && read(fd, &result, sizeof(result)) == sizeof(result) && close(fd) == 0);
    return result;
}

int main(int argc, char** argv) {
    CHECK(argc == 2 && !getuid() && !geteuid() && !getegid());
    CHECK(mkdir(argv[1], 0755) == 0 && chmod(argv[1], 0755) == 0);
    char directory[4096], file[4096];
    path(directory, argv[1], "records");
    struct account_login_frame frame;
    unsigned char token[16] = {1};
    CHECK(account_login_frame_make(&frame, ACCOUNT_LOGIN_START, "alice", 1000, 1000, 42,
                                   "/dev/pts/0", NULL, 0, token) == 0);
    account_login_frame_seal(&frame, 1);
    CHECK(account_login_frame_valid(&frame, 1));
    unsigned negatives = 0;
    for (size_t i = 0; i < sizeof(frame); i++)
        for (unsigned bit = 0; bit < 8; bit++) {
            struct account_login_frame changed = frame;
            ((unsigned char*)&changed)[i] ^= 1u << bit;
            CHECK(!account_login_frame_valid(&changed, 1));
            negatives++;
        }
    struct account_login_frame changed = frame;
    changed.entry.user[10] = 'x';
    account_login_frame_seal(&changed, 1);
    CHECK(!account_login_frame_valid(&changed, 1));
    changed = frame;
    changed.kind = ACCOUNT_LOGIN_END;
    account_login_frame_seal(&changed, 1);
    CHECK(!account_login_frame_valid(&changed, 1));
    CHECK(negatives == 3584);
    observed("3584_bit_corruptions_and_checksum_correct_malformed_fields_denied");
    mode_t old = umask(0777);
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(directory, 1, &book) == 0);
    CHECK(account_logbook_audit(book, ACCOUNT_LOGIN_BOOT, "", 0, NULL, NULL, 0) == 0);
    account_logbook_close(book);
    umask(old);
    const char* names[] = {"lock", "journal", "utmp", "wtmp", "btmp", "auth.log"};
    for (size_t i = 0; i < 6; i++) {
        path(file, directory, names[i]);
        struct stat value;
        CHECK(stat(file, &value) == 0 && S_ISREG(value.st_mode) && !value.st_uid && !value.st_gid);
        CHECK(value.st_nlink == 1 && (value.st_mode & 07777) == (i == 2 || i == 3 ? 0644 : 0600));
    }
    observed("protected_files_and_exact_modes_survive_restrictive_umask");
    struct child child;
    child_start(&child);
    struct account_profile profile = {.name = "alice", .uid = 1000, .gid = 1000};
    struct account_session_lease* lease = NULL;
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    CHECK(account_logbook_begin(book, &profile, child.pid, child.terminal, &lease) == 0 && lease);
    account_logbook_close(book);
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    CHECK(account_logbook_active(book, 1000) == 1 && account_logbook_active(book, 1001) == 0);
    CHECK(account_logbook_audit(book, ACCOUNT_LOGIN_BOOT, "", 0, NULL, NULL, 0) == -1 &&
          errno == EBUSY);
    struct account_login_entry live = entry(directory);
    CHECK(live.type == 7 && live.pid == child.pid && !strncmp(live.user, "alice", 32));
    CHECK(live.session == child.pid);
    account_logbook_close(book);
    observed("real_live_child_and_supervisor_lease_keep_user_active_across_reopen");
    pid_t ordinary = fork();
    CHECK(ordinary >= 0);
    if (!ordinary) {
        CHECK(setgroups(0, NULL) == 0 && setresgid(1001, 1001, 1001) == 0 &&
              setresuid(1001, 1001, 1001) == 0);
        path(file, directory, "journal");
        CHECK(open(file, O_RDONLY) == -1 && errno == EACCES);
        CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EPERM);
        path(file, directory, "utmp");
        int fd = open(file, O_RDONLY);
        CHECK(fd >= 0 && close(fd) == 0);
        _exit(0);
    }
    reap(ordinary);
    observed("ordinary_user_reads_public_utmp_but_cannot_read_journal_or_administer");
    child_finish(&child);
    CHECK(account_logbook_end(lease, 0) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == 0 &&
          account_logbook_active(book, 1000) == 0);
    live = entry(directory);
    CHECK(live.type == 8 && !live.user[0]);
    CHECK(account_logbook_audit(book, ACCOUNT_LOGIN_DENIED, "missing", (uid_t)-1, NULL, "/dev/tty",
                                1) == 0);
    CHECK(account_logbook_audit(book, ACCOUNT_LOGIN_SUDO, "alice", 1000, "root", "/dev/tty", 0) ==
          0);
    account_logbook_close(book);
    observed("normal_logout_dead_utmp_failed_login_btmp_and_elevation_audit");
    child_start(&child);
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t supervisor = fork();
    CHECK(supervisor >= 0);
    if (!supervisor) {
        close(ready[0]);
        CHECK(account_logbook_open(directory, 0, &book) == 0);
        CHECK(account_logbook_begin(book, &profile, child.pid, child.terminal, &lease) == 0);
        account_logbook_close(book);
        byte(ready[1], 1);
        for (;;)
            pause();
    }
    close(ready[1]);
    byte(ready[0], 0);
    close(ready[0]);
    CHECK(kill(supervisor, SIGKILL) == 0);
    int status;
    CHECK(waitpid(supervisor, &status, 0) == supervisor && WIFSIGNALED(status));
    CHECK(account_logbook_open(directory, 0, &book) == 0 &&
          account_logbook_active(book, 1000) == 0);
    account_logbook_close(book);
    live = entry(directory);
    CHECK(live.type == 8);
    child_finish(&child);
    observed("actual_sigkill_releases_supervisor_lease_recovered_exit_is_distinct");
    path(file, directory, "journal");
    int fd = open(file, O_RDWR | O_APPEND);
    CHECK(fd >= 0);
    struct stat before, after;
    CHECK(fstat(fd, &before) == 0 && write(fd, "partial", 7) == 7 && fsync(fd) == 0 &&
          close(fd) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    account_logbook_close(book);
    CHECK(stat(file, &after) == 0 && after.st_size == before.st_size);
    observed("partial_last_write_trimmed_only_after_validating_all_complete_frames");
    fd = open(file, O_RDWR);
    CHECK(fd >= 0 && pread(fd, &frame, sizeof(frame), 0) == sizeof(frame));
    changed = frame;
    changed.entry.user[0] ^= 1;
    CHECK(pwrite(fd, &changed, sizeof(changed), 0) == sizeof(changed) && fsync(fd) == 0 &&
          close(fd) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == -1 && errno == EUCLEAN);
    fd = open(file, O_RDWR);
    CHECK(fd >= 0 && pwrite(fd, &frame, sizeof(frame), 0) == sizeof(frame) && fsync(fd) == 0 &&
          close(fd) == 0);
    CHECK(account_logbook_open(directory, 0, &book) == 0);
    account_logbook_close(book);
    observed("complete_corrupt_frame_fails_closed_without_discarding_history");
    printf("ACCOUNT_LOGBOOK_PASS observations=%u damaged_bits=%u\n", observations, negatives);
    return 0;
}
