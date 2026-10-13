// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/auth.h"
#include "../../accounts/busy.h"
#include "../../accounts/database.h"
#include "../../accounts/home.h"
#include "../../accounts/password.h"
#include "../../accounts/session.h"
#include "../../accounts/recorded.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_SESSION_FAIL line=%d errno=%d expression=%s\n", __LINE__,     \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static const char* session_database;
static char session_records[4096];
static const char* manager;
static int delay_next_end;
static const char secret[] = "Fixture-only-Session-Authentication-82";

static void observed(const char* name) {
    printf("\nACCOUNT_SESSION_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void transfer(int fd, void* bytes, size_t size, int writing) {
    size_t done = 0;
    while (done < size) {
        struct pollfd item = {fd, writing ? POLLOUT : POLLIN, 0};
        CHECK(poll(&item, 1, 10000) == 1 && (item.revents & item.events));
        ssize_t count = writing ? write(fd, (char*)bytes + done, size - done)
                                : read(fd, (char*)bytes + done, size - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
}

static void path(char output[4096], const char* parent, const char* name) {
    CHECK(snprintf(output, 4096, "%s/%s", parent, name) < 4096);
}

struct start {
    pid_t pid;
    char terminal[64];
};

struct frontend {
    struct account_recorded_session recorded;
    struct account_profile* profile;
    pid_t pid;
    int master, slave, notice[2], allow[2];
    struct start session;
    int begin_count, end_count, deny_begin, delay_end;
    char record[4096];
};

static int begin(void* context, pid_t pid, const char* terminal) {
    struct frontend* front = context;
    CHECK(!geteuid() && !getegid());
    front->begin_count++;
    int record = open(front->record, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(record >= 0);
    CHECK(dprintf(record, "START pid=%d tty=%s uid=%u\n", (int)pid, terminal,
                  (unsigned)front->profile->uid) > 0 &&
          fsync(record) == 0 && close(record) == 0);
    struct stat value;
    CHECK(stat(terminal, &value) == 0 && value.st_uid == front->profile->uid);
    CHECK(value.st_gid == front->profile->gid && (value.st_mode & 0777) == 0600);
    struct start started = {pid, {0}};
    CHECK(strlen(terminal) < sizeof(started.terminal));
    strcpy(started.terminal, terminal);
    transfer(front->notice[1], &started, sizeof(started), 1);
    char allowed;
    transfer(front->allow[0], &allowed, 1, 0);
    CHECK(allowed == 'x');
    if (front->deny_begin) {
        errno = EACCES;
        return -1;
    }
    return account_recorded_begin(&front->recorded, pid, terminal);
}

static int end(void* context, pid_t pid, int status) {
    struct frontend* front = context;
    CHECK(!geteuid() && !getegid());
    front->end_count++;
    int record = open(front->record, O_WRONLY | O_APPEND | O_CLOEXEC);
    CHECK(record >= 0);
    CHECK(dprintf(record, "END pid=%d status=%d\n", (int)pid, status) > 0 && fsync(record) == 0 &&
          close(record) == 0);
    if (front->delay_end) {
        char byte = 'x';
        transfer(front->notice[1], &byte, 1, 1);
        transfer(front->allow[0], &byte, 1, 0);
        CHECK(byte == 'x');
    }
    return account_recorded_end(&front->recorded, pid, status);
}

static void start(struct frontend* front, struct account_profile* profile, const char* record,
                  char* const command[], int expected_error, int expected_exit) {
    *front = (struct frontend){
        .profile = profile, .deny_begin = expected_error == EACCES, .delay_end = delay_next_end};
    delay_next_end = 0;
    front->recorded = (struct account_recorded_session){.database = session_database,
                                                        .records = session_records,
                                                        .target = profile,
                                                        .operation = ACCOUNT_LOGIN_START,
                                                        .actor = 0};
    CHECK(strlen(record) < sizeof(front->record));
    strcpy(front->record, record);
    front->master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(front->master >= 0 && grantpt(front->master) == 0 && unlockpt(front->master) == 0);
    char terminal[64];
    CHECK(ptsname_r(front->master, terminal, sizeof(terminal)) == 0);
    front->slave = open(terminal, O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(front->slave >= 0 && pipe(front->notice) == 0 && pipe(front->allow) == 0);
    front->pid = fork();
    CHECK(front->pid >= 0);
    if (!front->pid) {
        close(front->master);
        close(front->notice[0]);
        close(front->allow[1]);
        CHECK(setsid() == getpid() && ioctl(front->slave, TIOCSCTTY, 0) == 0);
        struct termios before = {0}, after = {0};
        CHECK(tcgetattr(front->slave, &before) == 0);
        int flags = fcntl(front->slave, F_GETFL), status;
        CHECK(flags >= 0 && setenv("SESSION_FORGED", "inherited", 1) == 0);
        struct account_session_events events = {.begin = begin, .end = end, .context = front};
        int result = account_session_run(profile, front->slave, "vt100", command, &events, &status);
        if (expected_error)
            CHECK(result == -1 && errno == expected_error);
        else
            CHECK(result == 0 && WIFEXITED(status) && WEXITSTATUS(status) == expected_exit);
        CHECK(tcgetattr(front->slave, &after) == 0 && before.c_lflag == after.c_lflag);
        CHECK(before.c_iflag == after.c_iflag && before.c_oflag == after.c_oflag);
        CHECK(fcntl(front->slave, F_GETFL) == flags && tcgetpgrp(front->slave) == getpgrp());
        CHECK(front->begin_count == 1 && front->end_count == 1);
        _exit(0);
    }
    close(front->notice[1]);
    close(front->allow[0]);
    transfer(front->notice[0], &front->session, sizeof(front->session), 0);
    CHECK(front->session.pid > 0);
}

static void allow(struct frontend* front) {
    char byte = 'x';
    transfer(front->allow[1], &byte, 1, 1);
}

static void active(int alice, int bob) {
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(session_records, 0, &book) == 0);
    CHECK(account_logbook_active(book, 1000) == alice);
    CHECK(account_logbook_active(book, 1001) == bob);
    account_logbook_close(book);
}

static void administration(const char* operation, const char* name, const char* extra, int expected,
                           int unchanged) {
    struct account_database* db = NULL;
    char revision[35];
    CHECK(account_database_begin(session_database, 0, &db) == 0);
    strcpy(revision, account_database_revision(db));
    account_database_end(db);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char* arguments[] = {(char*)manager, "--database",    (char*)session_database,
                             "--records",    session_records, (char*)operation,
                             (char*)name,    (char*)extra,    NULL};
        execv(manager, arguments);
        _exit(99);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == expected);
    CHECK(account_database_begin(session_database, 0, &db) == 0);
    if (unchanged)
        CHECK(!strcmp(revision, account_database_revision(db)));
    account_database_end(db);
}

static void until(struct frontend* front, const char* marker) {
    char transcript[16384] = {0};
    size_t used = 0;
    while (!strstr(transcript, marker)) {
        struct pollfd item = {front->master, POLLIN, 0};
        CHECK(poll(&item, 1, 10000) == 1 && (item.revents & POLLIN));
        ssize_t count = read(front->master, transcript + used, sizeof(transcript) - used - 1);
        CHECK(count > 0);
        used += (size_t)count;
        CHECK(used < sizeof(transcript) - 1 && !strstr(transcript, "ACCOUNT_SESSION_FAIL"));
    }
    fputs(transcript, stdout);
    fflush(stdout);
}

static void finish(struct frontend* front) {
    int status;
    CHECK(waitpid(front->pid, &status, 0) == front->pid && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);
    struct stat value;
    CHECK(stat(front->session.terminal, &value) == -1 && errno == ENOENT);
    CHECK(stat(front->record, &value) == 0 && !value.st_uid && !value.st_gid &&
          (value.st_mode & 0777) == 0600);
    close(front->master);
    close(front->slave);
    close(front->notice[0]);
    close(front->allow[1]);
}

static void process_failure(struct account_profile* profile, const char* record,
                            char* const command[], int signal) {
    struct frontend front;
    start(&front, profile, record, command, 0, 0);
    struct termios before = {0}, after = {0};
    CHECK(tcgetattr(front.slave, &before) == 0);
    int flags = fcntl(front.slave, F_GETFL);
    allow(&front);
    until(&front, "SESSION_PROCESS_ACTIVE");
    if (signal == SIGHUP)
        close(front.master);
    else
        CHECK(kill(front.pid, signal) == 0);
    int status;
    CHECK(waitpid(front.pid, &status, 0) == front.pid && WIFSIGNALED(status) &&
          WTERMSIG(status) == signal);
    struct stat value;
    CHECK(stat(front.session.terminal, &value) == -1 && errno == ENOENT);
    if (signal == SIGTERM) {
        CHECK(tcgetattr(front.slave, &after) == 0 && before.c_lflag == after.c_lflag);
        CHECK(before.c_iflag == after.c_iflag && before.c_oflag == after.c_oflag);
        CHECK(fcntl(front.slave, F_GETFL) == flags);
        CHECK(kill(front.session.pid, 0) == -1 && errno == ESRCH);
        FILE* log = fopen(front.record, "r");
        CHECK(log);
        char text[512] = {0};
        CHECK(fread(text, 1, sizeof(text) - 1, log) > 0 && fclose(log) == 0);
        CHECK(strstr(text, "END pid="));
    }
    if (signal != SIGHUP)
        close(front.master);
    close(front.slave);
    close(front.notice[0]);
    close(front.allow[1]);
    active(0, 0);
}

int main(int argc, char** argv) {
    CHECK(argc == 5 && !getuid() && !geteuid() && !getegid());
    manager = argv[4];
    CHECK(mkdir(argv[1], 0755) == 0 && chmod(argv[1], 0755) == 0);
    char database[4096], homes[2][4096], private_files[2][4096], records[2][4096];
    path(database, argv[1], "db");
    session_database = database;
    path(session_records, argv[1], "login-records");
    char encoded[ACCOUNT_PASSWORD_HASH_SIZE];
    CHECK(account_password_hash(secret, encoded) == 0);
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 1, &db) == 0);
    for (unsigned i = 0; i < 2; i++) {
        const char* name = i ? "bob" : "alice";
        path(homes[i], argv[1], name);
        path(private_files[i], homes[i], "private");
        path(records[i], argv[1], i ? "bob-record" : "alice-record");
        int created;
        CHECK(account_home_create(homes[i], 1000 + i, 1000 + i, &created) == 0 && created);
        int file = open(private_files[i], O_WRONLY | O_CREAT | O_EXCL, 0600);
        CHECK(file >= 0 && fchown(file, 1000 + i, 1000 + i) == 0 && close(file) == 0);
        struct account_group group = {name, 1000 + i, NULL, 0};
        CHECK(account_database_put_group(db, NULL, &group) == 0);
        struct account_user user = {name,      encoded,  "",       homes[i],
                                    "/bin/sh", 1000 + i, 1000 + i, {-1, 0, -1, -1, -1, -1}};
        CHECK(account_database_put_user(db, NULL, &user) == 0);
    }
    struct account_group shared = {"shared", 1002, NULL, 0};
    CHECK(account_database_put_group(db, NULL, &shared) == 0);
    CHECK(account_database_member(db, "shared", "alice", 1) == 0);
    CHECK(account_database_member(db, "shared", "bob", 1) == 0);
    int published;
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    account_password_clear(encoded, sizeof(encoded));
    struct account_profile* profiles[2] = {NULL, NULL};
    CHECK(account_auth_password(database, "alice", "wrong", 0, &profiles[0]) ==
          ACCOUNT_AUTH_DENIED);
    CHECK(account_auth_password(database, "alice", secret, 0, &profiles[0]) ==
          ACCOUNT_AUTH_ACCEPTED);
    CHECK(account_auth_password(database, "bob", secret, 0, &profiles[1]) == ACCOUNT_AUTH_ACCEPTED);
    observed("wrong_password_denied_two_complete_authenticated_profiles");
    int null = open("/dev/null", O_RDWR), status;
    char* shell[] = {argv[2], "sh", "-i", NULL};
    CHECK(null >= 0 &&
          account_session_run(profiles[0], null, "vt100", shell, NULL, &status) == -1 &&
          errno == ENOTTY);
    close(null);
    observed("nonterminal_session_denied_without_exec");
    struct frontend fronts[2];
    delay_next_end = 1;
    start(&fronts[0], profiles[0], records[0], shell, 0, 0);
    start(&fronts[1], profiles[1], records[1], shell, 0, 0);
    CHECK(fronts[0].session.pid != fronts[1].session.pid);
    CHECK(strcmp(fronts[0].session.terminal, fronts[1].session.terminal) != 0);
    administration("user-delete", "alice", NULL, 1, 1);
    administration("group-rename", "shared", "renamed", 1, 1);
    active(0, 0);
    observed("installed_identity_before_session_registration_still_blocks_structural_changes");
    allow(&fronts[0]);
    allow(&fronts[1]);
    for (unsigned i = 0; i < 2; i++) {
        char command[16384];
        int size =
            snprintf(command, sizeof(command), "%s %u %u %s %d %s %d %s\n", argv[3], 1000 + i,
                     1000 + i, homes[i], (int)fronts[i].session.pid, private_files[1 - i],
                     (int)fronts[1 - i].session.pid, i ? "bob" : "alice");
        CHECK(size > 0 && size < (int)sizeof(command));
        transfer(fronts[i].master, command, (size_t)size, 1);
        until(&fronts[i], "ACCOUNT_SHELL_SESSION_PASS");
    }
    active(1, 1);
    observed("two_concurrent_real_shells_private_ptys_durable_records_cross_user_denial");
    administration("user-delete", "alice", NULL, 1, 1);
    administration("user-rename", "alice", "renamed", 1, 1);
    administration("user-home", "alice", "/home/changed", 1, 1);
    administration("group-rename", "shared", "renamed", 1, 1);
    administration("group-delete", "shared", NULL, 1, 1);
    administration("lock", "alice", NULL, 0, 0);
    administration("unlock", "alice", NULL, 0, 0);
    administration("member-delete", "shared", "alice", 0, 0);
    administration("member-add", "shared", "alice", 0, 0);
    observed(
        "live_identity_changes_denied_without_publication_policy_revocation_remains_available");
    for (unsigned i = 0; i < 2; i++) {
        char exit_command[] = "exit 0\n";
        transfer(fronts[i].master, exit_command, strlen(exit_command), 1);
        if (!i) {
            char byte;
            transfer(fronts[i].notice[0], &byte, 1, 0);
            CHECK(byte == 'x' && account_process_busy(1000, (gid_t)-1) == 0);
            active(1, 1);
            administration("user-delete", "alice", NULL, 1, 1);
            allow(&fronts[i]);
            observed("live_supervisor_lease_blocks_removal_after_child_exit_before_logout_record");
        }
        finish(&fronts[i]);
        char created[4096];
        path(created, homes[i], "session-created");
        struct stat value;
        CHECK(stat(created, &value) == 0 && value.st_uid == 1000 + i && value.st_gid == 1000 + i);
        CHECK((value.st_mode & 0777) == 0600);
    }
    active(0, 0);
    observed("normal_logout_durable_record_private_terminal_and_supervisor_cleanup");
    administration("user-home", "alice", homes[0], 0, 0);
    administration("group-rename", "shared", "sharing", 0, 0);
    administration("group-rename", "sharing", "shared", 0, 0);
    for (unsigned i = 0; i < 2; i++) {
        account_profile_free(profiles[i]);
        profiles[i] = NULL;
        CHECK(account_auth_password(database, i ? "bob" : "alice", secret, 0, &profiles[i]) ==
              ACCOUNT_AUTH_ACCEPTED);
    }
    observed("structural_updates_resume_after_logout_and_require_fresh_authenticated_generation");
    char denied_record[4096];
    path(denied_record, argv[1], "denied-record");
    char* denied_command[] = {argv[2], "sh", "-c", "echo FORBIDDEN_SESSION_EXEC", NULL};
    struct frontend denied;
    start(&denied, profiles[0], denied_record, denied_command, EACCES, 0);
    allow(&denied);
    finish(&denied);
    observed("failed_begin_record_prevents_exec_and_cleans_owned_child");
    char failed_record[4096];
    path(failed_record, argv[1], "failed-exec-record");
    char* missing[] = {"/missing-account-session-executable", NULL};
    struct frontend failed_exec;
    start(&failed_exec, profiles[0], failed_record, missing, 0, 127);
    allow(&failed_exec);
    finish(&failed_exec);
    observed("actual_failed_exec_status127_terminal_and_record_cleanup");
    char block[641];
    for (size_t i = 0; i < sizeof(block) - 1; i++)
        block[i] = '0' + i % 10;
    block[640] = 0;
    char burst_command[2048];
    CHECK(snprintf(burst_command, sizeof(burst_command),
                   "i=0; while [ $i -lt 64 ]; do printf '%%s' '%s'; i=$((i+1)); done",
                   block) < (int)sizeof(burst_command));
    char* burst[] = {argv[2], "sh", "-c", burst_command, NULL};
    struct frontend bursting;
    path(failed_record, argv[1], "burst-record");
    start(&bursting, profiles[0], failed_record, burst, 0, 0);
    allow(&bursting);
    for (size_t position = 0; position < 40960; position += 1024) {
        char bytes[1024];
        transfer(bursting.master, bytes, sizeof(bytes), 0);
        for (size_t i = 0; i < sizeof(bytes); i++)
            CHECK(bytes[i] == (char)('0' + (position + i) % 10));
    }
    finish(&bursting);
    observed("40960_exact_output_bytes_survive_exit_and_backpressure");
    char command[8192];
    CHECK(snprintf(command, sizeof(command), "echo SESSION_PROCESS_ACTIVE; exec %s sleep 30",
                   argv[2]) < (int)sizeof(command));
    char* sleeping[] = {argv[2], "sh", "-c", command, NULL};
    path(failed_record, argv[1], "terminated-record");
    process_failure(profiles[0], failed_record, sleeping, SIGTERM);
    observed("terminated_supervisor_reaps_child_records_logout_restores_terminal");
    path(failed_record, argv[1], "disconnected-record");
    process_failure(profiles[0], failed_record, sleeping, SIGHUP);
    observed("caller_terminal_disconnect_cleans_private_session_without_output_hang");
    path(failed_record, argv[1], "killed-record");
    process_failure(profiles[0], failed_record, sleeping, SIGKILL);
    observed("killed_supervisor_hangs_up_and_recovers_its_stale_durable_record");
    CHECK(account_database_begin(database, 0, &db) == 0);
    struct account_user changed = *account_database_user(db, "alice");
    changed.gecos = "Changed after authentication";
    CHECK(account_database_put_user(db, "alice", &changed) == 0);
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    path(failed_record, argv[1], "stale-authentication-record");
    struct frontend stale;
    start(&stale, profiles[0], failed_record, denied_command, ESTALE, 0);
    allow(&stale);
    finish(&stale);
    active(0, 0);
    observed("changed_database_revision_denies_stale_authenticated_profile_before_exec");
    account_profile_free(profiles[0]);
    account_profile_free(profiles[1]);
    printf("ACCOUNT_SESSION_PASS observations=%u authenticated_shells=2\n", observations);
    return 0;
}
