// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/database.h"
#include "../../accounts/password.h"
#include "../../accounts/store.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "ACCOUNT_MANAGEMENT_EXT2_FAIL line=%d errno=%d expression=%s\n",       \
                    __LINE__, errno, #condition);                                                  \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const char *secret = "Fixture-only-Administrator-42",
                  *changed = "Fixture-only-New-Secret-73";
static char database[1024], records[1024], homes[1024], root_path[1024];
static const char* accountctl;
static unsigned observations, commands;

static void path(char output[1024], const char* parent, const char* name) {
    int count = snprintf(output, 1024, "%s/%s", parent, name);
    CHECK(count > 0 && count < 1024);
}

static void all(int fd, const void* bytes, size_t size) {
    size_t done = 0;
    while (done < size) {
        ssize_t count = write(fd, (const char*)bytes + done, size - done);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count > 0);
        done += (size_t)count;
    }
}

static void observed(const char* name) {
    printf("ACCOUNT_MANAGEMENT_EXT2_OBSERVED case=%s\n", name);
    observations++;
}

struct snapshot {
    char revision[35];
    char* bytes[3];
    size_t sizes[3];
};

static struct snapshot snapshot(void) {
    struct account_store* store = NULL;
    CHECK(account_store_begin(database, 0, &store) == 0);
    const char* revision = account_store_revision(store);
    const struct account_content* content = account_store_snapshot(store);
    CHECK(revision && strlen(revision) == 34 && content);
    struct snapshot result = {0};
    memcpy(result.revision, revision, 35);
    for (unsigned i = 0; i < 3; i++) {
        result.sizes[i] = content[i].size;
        result.bytes[i] = malloc(content[i].size + 1);
        CHECK(result.bytes[i]);
        memcpy(result.bytes[i], content[i].data, content[i].size);
        result.bytes[i][content[i].size] = 0;
    }
    account_store_end(store);
    return result;
}

static struct snapshot readonly_snapshot(void) {
    // A genuinely read-only device cannot open the administration lock for
    // writing. There can be no concurrent writer; read the immutable files
    // directly rather than relaxing the production lock contract.
    struct snapshot result = {0};
    char name[1024];
    path(name, database, "current");
    CHECK(readlink(name, result.revision, sizeof(result.revision)) == 34);
    for (unsigned i = 0; i < 3; i++) {
        int length = snprintf(name, sizeof(name), "%s/%s/%s", database, result.revision,
                              (const char*[]){"passwd", "group", "shadow"}[i]);
        CHECK(length > 0 && length < (int)sizeof(name));
        int fd = open(name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat value;
        CHECK(fd >= 0 && fstat(fd, &value) == 0 && S_ISREG(value.st_mode) && value.st_size > 0 &&
              value.st_size <= ACCOUNT_FILE_LIMIT);
        result.sizes[i] = (size_t)value.st_size;
        result.bytes[i] = malloc(result.sizes[i] + 1);
        CHECK(result.bytes[i]);
        size_t done = 0;
        while (done < result.sizes[i]) {
            ssize_t count = read(fd, result.bytes[i] + done, result.sizes[i] - done);
            if (count < 0 && errno == EINTR)
                continue;
            CHECK(count > 0);
            done += (size_t)count;
        }
        result.bytes[i][done] = 0;
        char eof;
        CHECK(read(fd, &eof, 1) == 0 && close(fd) == 0);
    }
    return result;
}

static int equal(const struct snapshot* first, const struct snapshot* second) {
    if (strcmp(first->revision, second->revision))
        return 0;
    for (unsigned i = 0; i < 3; i++)
        if (first->sizes[i] != second->sizes[i] ||
            memcmp(first->bytes[i], second->bytes[i], first->sizes[i]))
            return 0;
    return 1;
}

static void release_snapshot(struct snapshot* value) {
    for (unsigned i = 0; i < 3; i++) {
        memset(value->bytes[i], 0, value->sizes[i]);
        free(value->bytes[i]);
    }
}

static pid_t launch(const char* const* arguments, const char* password, int ordinary) {
    int input[2];
    CHECK(pipe2(input, O_CLOEXEC) == 0);
    if (password) {
        all(input[1], password, strlen(password));
        all(input[1], "\n", 1);
    }
    CHECK(close(input[1]) == 0);
    fflush(NULL);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(dup2(input[0], 0) == 0 && close(input[0]) == 0);
        if (ordinary)
            CHECK(setgroups(0, NULL) == 0 && setresgid(80001, 80001, 80001) == 0 &&
                  setresuid(70001, 70001, 70001) == 0);
        const char* argv[32] = {accountctl, "--database", database, "--records", records};
        size_t count = 5;
        while (*arguments) {
            CHECK(count < 31);
            argv[count++] = *arguments++;
        }
        execv(accountctl, (char* const*)argv);
        _exit(127);
    }
    CHECK(close(input[0]) == 0);
    return child;
}

static int finish(pid_t child, const char* label) {
    int status;
    pid_t result;
    do {
        result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    CHECK(result == child);
    printf("ACCOUNT_MANAGEMENT_EXT2_COMMAND label=%s pid=%d status=%d\n", label, (int)child,
           status);
    commands++;
    return status;
}

static uint64_t monotonic(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static int sleeping_command(pid_t pid) {
    char name[1024], bytes[4096];
    int count = snprintf(name, sizeof(name), "/proc/%d/status", (int)pid);
    CHECK(count > 0 && count < (int)sizeof(name));
    int fd = open(name, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    ssize_t size = read(fd, bytes, sizeof(bytes) - 1);
    CHECK(size > 0 && close(fd) == 0);
    bytes[size] = 0;
    // Exclude an exec child's inherited test-driver identity: only the actual
    // administration command can provide blocked-command evidence.
    if (!strstr(bytes, "Name:\taccountctl\n"))
        return 0;
    const char* state = strstr(bytes, "\nState:");
    CHECK(state);
    state += 7;
    while (*state == ' ' || *state == '\t')
        state++;
    return *state == 'S';
}

static void blocked_commands(const pid_t* children, size_t count) {
    uint64_t deadline = monotonic() + 10000;
    for (;;) {
        size_t sleeping = 0;
        for (size_t i = 0; i < count; i++)
            sleeping += sleeping_command(children[i]);
        if (sleeping == count)
            break;
        CHECK(monotonic() < deadline);
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    // These exec children have prefilled stdin and no output before the
    // production store flock. The parent owns that exact lock throughout.
    printf(
        "ACCOUNT_MANAGEMENT_EXT2_BLOCKED commands=%zu evidence=owned_database_flock_and_proc_S\n",
        count);
}

static int database_lock(void) {
    char name[1024];
    path(name, database, "lock");
    int fd = open(name, O_RDWR | O_CLOEXEC);
    CHECK(fd >= 0 && flock(fd, LOCK_EX) == 0);
    return fd;
}

static void command(const char* label, const char* const* arguments, int expected,
                    const char* password, int ordinary) {
    int status = finish(launch(arguments, password, ordinary), label);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

static void unchanged(const char* label, const char* const* arguments, int expected,
                      const char* password, int ordinary) {
    struct snapshot before = snapshot();
    command(label, arguments, expected, password, ordinary);
    struct snapshot after = snapshot();
    CHECK(equal(&before, &after));
    release_snapshot(&before);
    release_snapshot(&after);
}

static void directory(const char* name) {
    CHECK(mkdir(name, 0755) == 0 || errno == EEXIST);
    struct stat value;
    CHECK(lstat(name, &value) == 0 && S_ISDIR(value.st_mode) && !value.st_uid && !value.st_gid);
    CHECK(chmod(name, 0755) == 0);
}

static void metadata(const char* name, mode_t mode, uid_t uid, gid_t gid, int directory_file) {
    struct stat value;
    CHECK(lstat(name, &value) == 0 && (value.st_mode & 07777) == mode && value.st_uid == uid &&
          value.st_gid == gid &&
          (directory_file ? S_ISDIR(value.st_mode) : S_ISREG(value.st_mode)));
    if (!directory_file)
        CHECK(value.st_nlink == 1);
}

static void home_data(const char* name, uid_t uid, gid_t gid, int create) {
    char home[1024], file[1024];
    path(home, homes, name);
    metadata(home, 0700, uid, gid, 1);
    path(file, home, "retained.txt");
    if (create) {
        int fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        CHECK(fd >= 0);
        all(fd, "persistent private home data\n", 29);
        CHECK(fchown(fd, uid, gid) == 0 && fchmod(fd, 0600) == 0 && fsync(fd) == 0 &&
              close(fd) == 0);
    }
    metadata(file, 0600, uid, gid, 0);
    int fd = open(file, O_RDONLY | O_CLOEXEC);
    char bytes[30];
    CHECK(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 29 &&
          !memcmp(bytes, "persistent private home data\n", 29) && close(fd) == 0);
}

static void links(void) {
    const char* names[] = {"passwd", "group", "shadow"};
    for (unsigned i = 0; i < 3; i++) {
        char target[1024], link[1024];
        int count = snprintf(target, sizeof(target), "%s/current/%s", database, names[i]);
        CHECK(count > 0 && count < (int)sizeof(target));
        path(link, "/etc", names[i]);
        CHECK(symlink(target, link) == 0);
    }
}

static void lookup(const char* user_name, uid_t uid, gid_t gid, const char* group_name,
                   const char* password, int ordinary, int sudo_member) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        gid_t groups[16];
        CHECK(initgroups(user_name, gid) == 0);
        int count = getgroups(16, groups), primary = 0, sudo = 0;
        CHECK(count == 1 + sudo_member);
        for (int i = 0; i < count; i++) {
            primary += groups[i] == gid;
            sudo += groups[i] == 27;
        }
        CHECK(primary == 1 && sudo == sudo_member);
        if (ordinary)
            CHECK(setresgid(gid, gid, gid) == 0 && setresuid(uid, uid, uid) == 0);
        struct passwd pw, *user = NULL;
        struct group gr, *group = NULL;
        struct spwd sp, *shadow = NULL;
        char bytes[8192];
        CHECK(getpwnam_r(user_name, &pw, bytes, sizeof(bytes), &user) == 0 && user &&
              pw.pw_uid == uid && pw.pw_gid == gid);
        CHECK(getpwuid_r(uid, &pw, bytes, sizeof(bytes), &user) == 0 && user &&
              !strcmp(pw.pw_name, user_name));
        CHECK(getgrnam_r(group_name, &gr, bytes, sizeof(bytes), &group) == 0 && group &&
              gr.gr_gid == gid);
        CHECK(getgrgid_r(gid, &gr, bytes, sizeof(bytes), &group) == 0 && group &&
              !strcmp(gr.gr_name, group_name));
        if (ordinary) {
            CHECK(getspnam_r(user_name, &sp, bytes, sizeof(bytes), &shadow) != 0 && !shadow);
            CHECK(setuid(0) == -1 && errno == EPERM);
        } else {
            CHECK(getspnam_r(user_name, &sp, bytes, sizeof(bytes), &shadow) == 0 && shadow);
            CHECK(account_password_verify(password, sp.sp_pwdp) == 1);
            CHECK(account_password_verify("wrong-fixture-password", sp.sp_pwdp) == 0);
        }
        _exit(0);
    }
    int status = finish(child, ordinary ? "ordinary-libc-lookup" : "root-libc-lookup");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void export_snapshot(const struct snapshot* value, const char* phase) {
    printf("ACCOUNT_MANAGEMENT_EXT2_REVISION phase=%s value=%s\n", phase, value->revision);
    for (unsigned i = 0; i < 3; i++) {
        printf("ACCOUNT_MANAGEMENT_EXT2_DATA phase=%s name=%s hex=", phase,
               (const char*[]){"passwd", "group", "shadow"}[i]);
        for (size_t j = 0; j < value->sizes[i]; j++)
            printf("%02x", (unsigned char)value->bytes[i][j]);
        putchar('\n');
    }
    fflush(stdout);
}

static void inspect(const char* phase) {
    struct snapshot value = snapshot();
    metadata(database, 0755, 0, 0, 1);
    char name[1024];
    path(name, database, "lock");
    metadata(name, 0600, 0, 0, 0);
    path(name, database, value.revision);
    metadata(name, 0755, 0, 0, 1);
    for (unsigned i = 0; i < 3; i++) {
        const char* base = (const char*[]){"passwd", "group", "shadow"}[i];
        int count = snprintf(name, sizeof(name), "%s/%s/%s", database, value.revision, base);
        CHECK(count > 0 && count < (int)sizeof(name));
        metadata(name, i == 2 ? 0600 : 0644, 0, 0, 0);
    }
    export_snapshot(&value, phase);
    release_snapshot(&value);
}

static void prepare(void) {
    directory(root_path);
    directory(homes);
    char admin[1024], alice[1024], bob[1024], locked[1024], alternate[1024], control[1024];
    path(admin, homes, "admin");
    path(alice, homes, "alice");
    path(bob, homes, "bob");
    path(locked, homes, "locked");
    path(alternate, homes, "bob-new");
    command("bootstrap",
            (const char*[]){"bootstrap", "admin", admin, "/bin/sh", "--password-fd", "0", NULL}, 0,
            secret, 0);
    command("group-add-staff", (const char*[]){"group-add", "staff", "80000", NULL}, 0, NULL, 0);
    command("group-add-spare", (const char*[]){"group-add", "spare", "80002", NULL}, 0, NULL, 0);
    command("user-add-alice",
            (const char*[]){"user-add", "alice", "70000", "staff", alice, "/bin/sh", NULL}, 0, NULL,
            0);
    command("user-add-bob",
            (const char*[]){"user-add", "bob", "70001", "staff", bob, "/bin/sh", NULL}, 0, NULL, 0);
    command("user-add-locked",
            (const char*[]){"user-add", "locked", "70003", "staff", locked, "/bin/sh", NULL}, 0,
            NULL, 0);
    for (const char** user = (const char*[]){"alice", "locked", NULL}; *user; user++)
        command("password", (const char*[]){"password", *user, "--password-fd", "0", NULL}, 0,
                secret, 0);
    command("lock", (const char*[]){"lock", "locked", NULL}, 0, NULL, 0);
    command("member-add", (const char*[]){"member-add", "sudo", "alice", NULL}, 0, NULL, 0);
    CHECK(mkdir(alternate, 0700) == 0 && chown(alternate, 70001, 80000) == 0 &&
          chmod(alternate, 0700) == 0);
    home_data("admin", 1000, 1000, 1);
    home_data("alice", 70000, 80000, 1);
    home_data("bob", 70001, 80000, 1);
    home_data("bob-new", 70001, 80000, 1);
    home_data("locked", 70003, 80000, 1);
    path(control, root_path, "control");
    int fd = open(control, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    char block[4096] = {0};
    CHECK(fd >= 0);
    all(fd, block, sizeof(block));
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    observed("actual_bootstrap_groups_full_width_users_password_lock_membership_and_owned_homes");
}

static const char* const* selection(unsigned index, const char** password) {
    static const char* arguments[8];
    static char home[1024];
    memset(arguments, 0, sizeof(arguments));
    *password = NULL;
    const char* const cases[][7] = {{"bootstrap", "admin", NULL, "/bin/sh", "--password-fd", "0"},
                                    {"group-add", "extra", "80010"},
                                    {"group-delete", "spare"},
                                    {"group-rename", "spare", "renamed-group"},
                                    {"user-add", "charlie", "70002", "staff", NULL, "/bin/sh"},
                                    {"user-delete", "bob"},
                                    {"user-rename", "bob", "renamed-user"},
                                    {"user-home", "bob", NULL},
                                    {"user-shell", "bob", "/bin/busybox"},
                                    {"member-add", "sudo", "bob"},
                                    {"member-delete", "sudo", "alice"},
                                    {"password", "alice", "--password-fd", "0"},
                                    {"lock", "alice"},
                                    {"unlock", "locked"},
                                    {"show", "alice"}};
    CHECK(index < sizeof(cases) / sizeof(*cases));
    memcpy(arguments, cases[index], sizeof(cases[index]));
    if (!index || index == 4 || index == 7) {
        path(home, homes, !index ? "admin" : index == 4 ? "charlie" : "bob-new");
        arguments[!index ? 2 : index == 4 ? 4 : 2] = home;
    }
    if (!index || index == 11)
        *password = index ? changed : secret;
    return arguments;
}

static void ordinary_denials(void) {
    for (unsigned i = 0; i < 15; i++) {
        const char* password;
        const char* const* args = selection(i, &password);
        unchanged(args[0], args, 1, password, 1);
    }
    observed("all_fifteen_actual_commands_ordinary_denied_without_generation_or_payload_change");
}

static void mutation_result(unsigned index) {
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 0, &db) == 0);
    const struct account_user* user = account_database_user(db, index == 4    ? "charlie"
                                                                : index == 13 ? "locked"
                                                                : index >= 11 ? "alice"
                                                                              : "bob");
    const struct account_group* sudo_group = account_database_group(db, "sudo");
    char home[1024];
    switch (index) {
    case 1: {
        const struct account_group* group = account_database_group(db, "extra");
        CHECK(group && group->gid == 80010 && !group->member_count);
        break;
    }
    case 4:
        path(home, homes, "charlie");
        CHECK(user && user->uid == 70002 && user->gid == 80000 && !strcmp(user->home, home) &&
              !strcmp(user->shell, "/bin/sh") && !strcmp(user->password, "!"));
        metadata(home, 0700, 70002, 80000, 1);
        break;
    case 7:
        path(home, homes, "bob-new");
        CHECK(user && user->uid == 70001 && user->gid == 80000 && !strcmp(user->home, home));
        break;
    case 8:
        CHECK(user && user->uid == 70001 && user->gid == 80000 &&
              !strcmp(user->shell, "/bin/busybox"));
        break;
    case 9: {
        unsigned present = 0;
        CHECK(sudo_group);
        for (size_t i = 0; i < sudo_group->member_count; i++)
            present += sudo_group->members[i] == 70001;
        CHECK(present == 1);
        break;
    }
    case 10:
        CHECK(sudo_group);
        for (size_t i = 0; i < sudo_group->member_count; i++)
            CHECK(sudo_group->members[i] != 70000);
        break;
    case 11:
        CHECK(user && user->age[0] > 0 && account_password_verify(changed, user->password) == 1 &&
              account_password_verify(secret, user->password) == 0);
        break;
    case 12:
        CHECK(user && *user->password == '!' &&
              account_password_verify(changed, user->password) == 0);
        break;
    case 13:
        CHECK(user && *user->password != '!' &&
              account_password_verify(secret, user->password) == 1);
        break;
    case 14:
        CHECK(user && user->uid == 70000 && user->gid == 80000);
        break;
    default:
        CHECK(0);
    }
    account_database_end(db);
}

static void exercise(void) {
    ordinary_denials();
    const char* password;
    for (unsigned i = 1; i < 15; i++) {
        // Keep the user/group deletion and rename cases for the end so all
        // commands exercise real extant records and relationships first.
        if (i == 2 || i == 3 || i == 5 || i == 6)
            continue;
        const char* const* args = selection(i, &password);
        command(args[0], args, 0, password, 0);
        mutation_result(i);
    }
    command("unlock-alice", (const char*[]){"unlock", "alice", NULL}, 0, NULL, 0);
    lookup("alice", 70000, 80000, "staff", changed, 0, 0);
    lookup("alice", 70000, 80000, "staff", changed, 1, 0);
    command("group-rename", (const char*[]){"group-rename", "spare", "renamed-group", NULL}, 0,
            NULL, 0);
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 0, &db) == 0);
    const struct account_group* renamed_group = account_database_group(db, "renamed-group");
    CHECK(!account_database_group(db, "spare") && renamed_group && renamed_group->gid == 80002);
    account_database_end(db);
    command("group-delete", (const char*[]){"group-delete", "renamed-group", NULL}, 0, NULL, 0);
    command("user-rename", (const char*[]){"user-rename", "bob", "renamed-user", NULL}, 0, NULL, 0);
    CHECK(account_database_begin(database, 0, &db) == 0);
    const struct account_user* renamed_user = account_database_user(db, "renamed-user");
    CHECK(!account_database_user(db, "bob") && renamed_user && renamed_user->uid == 70001 &&
          renamed_user->gid == 80000 && !strcmp(renamed_user->shell, "/bin/busybox"));
    const struct account_group* sudo_group = account_database_group(db, "sudo");
    unsigned renamed_member = 0;
    CHECK(sudo_group);
    for (size_t i = 0; i < sudo_group->member_count; i++)
        renamed_member += sudo_group->members[i] == 70001;
    CHECK(renamed_member == 1);
    account_database_end(db);
    command("user-delete", (const char*[]){"user-delete", "renamed-user", NULL}, 0, NULL, 0);
    unchanged("duplicate-user",
              (const char*[]){"user-add", "alice", "70009", "staff", "/home/x", "/bin/sh", NULL}, 1,
              NULL, 0);
    unchanged(
        "duplicate-uid",
        (const char*[]){"user-add", "collision", "70000", "staff", "/home/x", "/bin/sh", NULL}, 1,
        NULL, 0);
    unchanged("duplicate-gid", (const char*[]){"group-add", "collision", "80000", NULL}, 1, NULL,
              0);
    unchanged("invalid-id", (const char*[]){"group-add", "invalid", "4294967295", NULL}, 1, NULL,
              0);
    unchanged("invalid-name", (const char*[]){"group-add", "bad:name", "80011", NULL}, 2, NULL, 0);
    unchanged("primary-group", (const char*[]){"group-delete", "staff", NULL}, 1, NULL, 0);
    unchanged("protected-root", (const char*[]){"user-delete", "root", NULL}, 1, NULL, 0);
    unchanged("missing", (const char*[]){"show", "missing", NULL}, 1, NULL, 0);
    unchanged("empty-password", (const char*[]){"password", "alice", "--password-fd", "0", NULL}, 2,
              "", 0);
    const char* unused_password;
    unchanged("duplicate-bootstrap", selection(0, &unused_password), 1, secret, 0);
    unchanged("root-unlock", (const char*[]){"unlock", "root", NULL}, 1, NULL, 0);
    char unsafe[1024], existing[1024];
    path(unsafe, homes, "unsafe-link");
    path(existing, homes, "bob");
    CHECK(symlink(existing, unsafe) == 0);
    unchanged("symlink-home",
              (const char*[]){"user-add", "unsafe-link", "73000", "staff", unsafe, "/bin/sh", NULL},
              1, NULL, 0);
    unchanged(
        "wrong-owner-home",
        (const char*[]){"user-add", "unsafe-owner", "73001", "staff", existing, "/bin/sh", NULL}, 1,
        NULL, 0);
    CHECK(unlink(unsafe) == 0);
    home_data("bob", 70001, 80000, 0);
    home_data("bob-new", 70001, 80000, 0);
    observed("all_root_commands_relationship_updates_and_deletion_preserve_home_data");
    observed(
        "duplicate_invalid_primary_group_root_missing_and_password_denials_preserve_generation");
}

static void verify(void) {
    lookup("alice", 70000, 80000, "staff", changed, 0, 1);
    lookup("alice", 70000, 80000, "staff", changed, 1, 1);
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 0, &db) == 0);
    CHECK(!account_database_user(db, "bob") && !account_database_user(db, "renamed-user") &&
          !account_database_group(db, "spare") && !account_database_group(db, "renamed-group"));
    const struct account_user* alice = account_database_user(db, "alice");
    CHECK(alice && account_password_verify(changed, alice->password) == 1);
    const struct account_user* root = account_database_user(db, "root");
    CHECK(root && root->uid == 0 && root->gid == 0 && !strcmp(root->password, "!"));
    account_database_end(db);
    home_data("admin", 1000, 1000, 0);
    home_data("alice", 70000, 80000, 0);
    home_data("bob", 70001, 80000, 0);
    home_data("bob-new", 70001, 80000, 0);
    home_data("locked", 70003, 80000, 0);
    for (int ordinary = 0; ordinary < 2; ordinary++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            if (ordinary)
                CHECK(setgroups(0, NULL) == 0 && setresgid(80000, 80000, 80000) == 0 &&
                      setresuid(70000, 70000, 70000) == 0);
            struct passwd value, *found = NULL;
            struct group group_value, *group_found = NULL;
            char bytes[4096], own[1024], other[1024];
            CHECK(getpwnam_r("bob", &value, bytes, sizeof(bytes), &found) == 0 && !found);
            CHECK(getpwuid_r(70001, &value, bytes, sizeof(bytes), &found) == 0 && !found);
            CHECK(getgrnam_r("spare", &group_value, bytes, sizeof(bytes), &group_found) == 0 &&
                  !group_found);
            CHECK(getgrgid_r(80002, &group_value, bytes, sizeof(bytes), &group_found) == 0 &&
                  !group_found);
            path(own, homes, "alice/retained.txt");
            int fd = open(own, O_RDONLY | O_CLOEXEC);
            CHECK(fd >= 0 && close(fd) == 0);
            if (ordinary) {
                path(other, homes, "bob/retained.txt");
                CHECK(open(other, O_RDONLY | O_CLOEXEC) == -1 && errno == EACCES);
                CHECK(open("/etc/shadow", O_RDONLY | O_CLOEXEC) == -1 && errno == EACCES);
            }
            _exit(0);
        }
        int status = finish(child, ordinary ? "ordinary-missing-libc-record-and-home-access"
                                            : "root-missing-libc-record-and-home-access");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    observed("fresh_process_lookup_protected_metadata_and_home_data_persist");
}

static void concurrent(void) {
    char names[12][33], ids[12][16];
    pid_t children[12];
    int lock = database_lock();
    for (unsigned i = 0; i < 12; i++) {
        CHECK(snprintf(names[i], sizeof(names[i]), "batch%u", i) > 0);
        CHECK(snprintf(ids[i], sizeof(ids[i]), "%u", 82000 + i) > 0);
        children[i] = launch((const char*[]){"group-add", names[i], ids[i], NULL}, NULL, 0);
    }
    blocked_commands(children, 12);
    CHECK(flock(lock, LOCK_UN) == 0 && close(lock) == 0);
    for (unsigned i = 0; i < 12; i++) {
        int status = finish(children[i], "concurrent-disjoint-group-add");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 0, &db) == 0);
    for (unsigned i = 0; i < 12; i++) {
        const struct account_group* group = account_database_group(db, names[i]);
        CHECK(group && group->gid == 82000 + i);
    }
    account_database_end(db);
    observed("twelve_actual_concurrent_disjoint_commits_preserve_every_group");
    lock = database_lock();
    children[0] = launch((const char*[]){"group-add", "winner-a", "83000", NULL}, NULL, 0);
    children[1] = launch((const char*[]){"group-add", "winner-b", "83000", NULL}, NULL, 0);
    blocked_commands(children, 2);
    CHECK(flock(lock, LOCK_UN) == 0 && close(lock) == 0);
    unsigned winners = 0;
    for (unsigned i = 0; i < 2; i++) {
        int status = finish(children[i], "concurrent-duplicate-gid");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) <= 1);
        winners += WEXITSTATUS(status) == 0;
    }
    CHECK(winners == 1 && account_database_begin(database, 0, &db) == 0);
    CHECK((account_database_group(db, "winner-a") != NULL) +
              (account_database_group(db, "winner-b") != NULL) ==
          1);
    account_database_end(db);
    char homes_race[2][1024];
    path(homes_race[0], homes, "racer-a");
    path(homes_race[1], homes, "racer-b");
    lock = database_lock();
    for (unsigned i = 0; i < 2; i++)
        children[i] = launch((const char*[]){"user-add", i ? "racer-b" : "racer-a", "71000",
                                             "staff", homes_race[i], "/bin/sh", NULL},
                             NULL, 0);
    blocked_commands(children, 2);
    CHECK(flock(lock, LOCK_UN) == 0 && close(lock) == 0);
    winners = 0;
    for (unsigned i = 0; i < 2; i++) {
        int status = finish(children[i], "concurrent-duplicate-uid");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) <= 1);
        struct stat value;
        if (!WEXITSTATUS(status)) {
            winners++;
            metadata(homes_race[i], 0700, 71000, 80000, 1);
        } else
            CHECK(lstat(homes_race[i], &value) == -1 && errno == ENOENT);
    }
    CHECK(winners == 1 && account_database_begin(database, 0, &db) == 0);
    const struct account_user* winner = account_database_uid(db, 71000);
    CHECK(winner && (!strcmp(winner->name, "racer-a") || !strcmp(winner->name, "racer-b")));
    account_database_end(db);
    observed("actual_duplicate_gid_and_uid_races_have_one_winner_and_no_losing_home");
    lock = database_lock();
    children[0] = launch((const char*[]){"group-add", "same-name", "83001", NULL}, NULL, 0);
    children[1] = launch((const char*[]){"group-add", "same-name", "83002", NULL}, NULL, 0);
    blocked_commands(children, 2);
    CHECK(flock(lock, LOCK_UN) == 0 && close(lock) == 0);
    winners = 0;
    for (unsigned i = 0; i < 2; i++) {
        int status = finish(children[i], "concurrent-duplicate-name");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) <= 1);
        winners += WEXITSTATUS(status) == 0;
    }
    CHECK(winners == 1 && account_database_begin(database, 0, &db) == 0);
    const struct account_group* same = account_database_group(db, "same-name");
    CHECK(same && (same->gid == 83001 || same->gid == 83002));
    account_database_end(db);
    char moved[1024];
    path(moved, homes, "charlie-updated");
    CHECK(mkdir(moved, 0700) == 0 && chown(moved, 70002, 80000) == 0 && chmod(moved, 0700) == 0);
    lock = database_lock();
    children[0] = launch((const char*[]){"user-shell", "charlie", "/bin/busybox", NULL}, NULL, 0);
    children[1] = launch((const char*[]){"user-home", "charlie", moved, NULL}, NULL, 0);
    blocked_commands(children, 2);
    CHECK(flock(lock, LOCK_UN) == 0 && close(lock) == 0);
    for (unsigned i = 0; i < 2; i++) {
        int status = finish(children[i], "concurrent-distinct-fields-same-user");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(account_database_begin(database, 0, &db) == 0);
    const struct account_user* charlie = account_database_user(db, "charlie");
    CHECK(charlie && !strcmp(charlie->home, moved) && !strcmp(charlie->shell, "/bin/busybox"));
    account_database_end(db);
    observed("actual_duplicate_name_has_one_winner_and_concurrent_user_fields_both_persist");
    lock = database_lock();
    const char* members[] = {"alice", "charlie", "locked"};
    for (unsigned i = 0; i < 3; i++)
        children[i] = launch((const char*[]){"member-add", "sudo", members[i], NULL}, NULL, 0);
    blocked_commands(children, 3);
    CHECK(flock(lock, LOCK_UN) == 0 && close(lock) == 0);
    for (unsigned i = 0; i < 3; i++) {
        int status = finish(children[i], "concurrent-membership-union");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(account_database_begin(database, 0, &db) == 0);
    for (unsigned i = 0; i < 3; i++) {
        const struct account_user* user = account_database_user(db, members[i]);
        gid_t groups[16];
        size_t count = 0;
        CHECK(user && account_database_groups(db, user->uid, groups, 16, &count) == 0);
        unsigned primary = 0, sudo = 0;
        for (size_t j = 0; j < count; j++) {
            primary += groups[j] == 80000;
            sudo += groups[j] == 27;
        }
        CHECK(count == 2 && primary == 1 && sudo == 1);
    }
    account_database_end(db);
    observed("actual_concurrent_membership_edits_preserve_the_complete_union");
    struct snapshot before = snapshot();
    char book_lock[1024], store_lock[1024];
    path(book_lock, records, "lock");
    path(store_lock, database, "lock");
    int book = open(book_lock, O_RDWR | O_CLOEXEC);
    int store = open(store_lock, O_RDWR | O_CLOEXEC);
    CHECK(book >= 0 && store >= 0 && flock(book, LOCK_EX) == 0);
    pid_t killed = launch((const char*[]){"group-add", "killed-pending", "84000", NULL}, NULL, 0);
    uint64_t deadline = monotonic() + 10000;
    for (;;) {
        int result = flock(store, LOCK_EX | LOCK_NB);
        if (result == -1) {
            CHECK(errno == EWOULDBLOCK || errno == EAGAIN);
            if (sleeping_command(killed))
                break;
        } else
            CHECK(flock(store, LOCK_UN) == 0);
        CHECK(monotonic() < deadline);
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    CHECK(kill(killed, SIGKILL) == 0);
    int status = finish(killed, "actual-command-killed-after-store-lock-before-journal-lock");
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    CHECK(flock(book, LOCK_UN) == 0 && close(book) == 0 && close(store) == 0);
    struct snapshot after = snapshot();
    CHECK(equal(&before, &after));
    release_snapshot(&before);
    release_snapshot(&after);
    command("retry-after-sigkill", (const char*[]){"group-add", "retry-after-kill", "84001", NULL},
            0, NULL, 0);
    observed("actual_command_holds_store_and_waits_journal_lock_sigkill_preserves_generation_then_"
             "retry");
}

static void control(const char* marker) {
    char name[1024], bytes[512] = {0};
    path(name, root_path, "control");
    CHECK(strlen(marker) < 64);
    memcpy(bytes, marker, strlen(marker));
    int fd = open(name, O_RDWR | O_CLOEXEC);
    CHECK(fd >= 0 && pwrite(fd, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes) &&
          fsync(fd) == 0 && close(fd) == 0);
}

static int fault_user_present(int interrupted) {
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 0, &db) == 0);
    const struct account_user* user = account_database_user(db, "fault-user");
    int present = user != NULL;
    char home[1024];
    path(home, homes, "fault-user");
    if (present) {
        CHECK(user->uid == 72000 && user->gid == 80000 && !strcmp(user->home, home) &&
              !strcmp(user->shell, "/bin/sh") && !strcmp(user->password, "!"));
        metadata(home, 0700, 72000, 80000, 1);
    } else {
        struct stat value;
        if (lstat(home, &value) == 0) {
            // A VM may disappear after creating its owned empty home but
            // before publishing the account. The explicit recovery retry may
            // adopt only that exact safe home; existing user data is retained.
            CHECK(interrupted);
            metadata(home, 0700, 72000, 80000, 1);
            DIR* directory = opendir(home);
            CHECK(directory);
            struct dirent* entry;
            errno = 0;
            while ((entry = readdir(directory)))
                CHECK(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."));
            CHECK(!errno && closedir(directory) == 0);
            printf("ACCOUNT_MANAGEMENT_EXT2_RECOVER orphan_owned_empty_home=1\n");
        } else
            CHECK(errno == ENOENT);
    }
    account_database_end(db);
    home_data("admin", 1000, 1000, 0);
    home_data("alice", 70000, 80000, 0);
    home_data("bob", 70001, 80000, 0);
    home_data("bob-new", 70001, 80000, 0);
    home_data("locked", 70003, 80000, 0);
    return present;
}

static void attempt(void) {
    struct snapshot before = snapshot();
    export_snapshot(&before, "before");
    CHECK(!fault_user_present(0));
    char home[1024];
    path(home, homes, "fault-user");
    control("AXIOM64_MANAGEMENT_ARM_v1");
    int status = finish(
        launch((const char*[]){"user-add", "fault-user", "72000", "staff", home, "/bin/sh", NULL},
               NULL, 0),
        "fault-user-add");
    // END is the first disk action after waitpid. Observer reads and unmount
    // belong outside the actual administration command's device epoch.
    control("AXIOM64_MANAGEMENT_END_v1");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) <= 1);
    int present = fault_user_present(0);
    struct snapshot after = snapshot();
    if (!present)
        CHECK(equal(&before, &after));
    CHECK(WEXITSTATUS(status) != 0 || present);
    printf("ACCOUNT_MANAGEMENT_EXT2_ATTEMPT exit=%d visible=%d\n", WEXITSTATUS(status), present);
    release_snapshot(&before);
    release_snapshot(&after);
    observed("actual_unmodified_user_add_device_epoch_and_complete_old_or_new_home_consistency");
}

static void recover(void) {
    int present = fault_user_present(1);
    printf("ACCOUNT_MANAGEMENT_EXT2_RECOVER visible=%d\n", present);
    inspect("recovered");
    if (!present) {
        char home[1024];
        path(home, homes, "fault-user");
        command("retry-after-storage-failure",
                (const char*[]){"user-add", "fault-user", "72000", "staff", home, "/bin/sh", NULL},
                0, NULL, 0);
    }
    CHECK(fault_user_present(0));
    unchanged(
        "retry-visible-user-rejects-duplicate",
        (const char*[]){"user-add", "fault-user", "72000", "staff", "/home/x", "/bin/sh", NULL}, 1,
        NULL, 0);
    observed("fresh_kernel_complete_generation_home_consistency_and_idempotent_command_retry");
}

static void full_volume(void) {
    struct snapshot before = snapshot();
    export_snapshot(&before, "before");
    char name[1024], home[1024], bytes[65536];
    memset(bytes, 0xa5, sizeof(bytes));
    path(name, root_path, "full-volume-filler");
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    uint64_t written = 0;
    for (;;) {
        ssize_t count = write(fd, bytes, sizeof(bytes));
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            CHECK(errno == ENOSPC);
            break;
        }
        CHECK(count > 0);
        written += (uint64_t)count;
        CHECK(written < 40 * 1024 * 1024);
    }
    CHECK(written > 1024 * 1024 && close(fd) == 0);
    printf("ACCOUNT_MANAGEMENT_EXT2_ENOSPC written=%llu errno=%d\n", (unsigned long long)written,
           ENOSPC);
    path(home, homes, "fault-user");
    unchanged("actual-full-volume-user-add",
              (const char*[]){"user-add", "fault-user", "72000", "staff", home, "/bin/sh", NULL}, 1,
              NULL, 0);
    CHECK(!fault_user_present(0) && unlink(name) == 0);
    command("retry-after-enospc",
            (const char*[]){"user-add", "fault-user", "72000", "staff", home, "/bin/sh", NULL}, 0,
            NULL, 0);
    CHECK(fault_user_present(0));
    release_snapshot(&before);
    observed("actual_ext2_enospc_preserves_generation_and_homes_then_clean_space_retry_commits");
}

static void readonly_volume(void) {
    struct statfs fs;
    CHECK(statfs(root_path, &fs) == 0 && (fs.f_flags & ST_RDONLY));
    struct snapshot before = readonly_snapshot();
    char home[1024];
    path(home, homes, "fault-user");
    command("actual-readonly-user-add",
            (const char*[]){"user-add", "fault-user", "72000", "staff", home, "/bin/sh", NULL}, 1,
            NULL, 0);
    struct snapshot after = readonly_snapshot();
    CHECK(equal(&before, &after));
    struct stat value;
    CHECK(lstat(home, &value) == -1 && errno == ENOENT);
    export_snapshot(&after, "readonly");
    release_snapshot(&before);
    release_snapshot(&after);
    home_data("admin", 1000, 1000, 0);
    home_data("alice", 70000, 80000, 0);
    home_data("bob", 70001, 80000, 0);
    home_data("bob-new", 70001, 80000, 0);
    home_data("locked", 70003, 80000, 0);
    observed(
        "actual_readonly_device_denies_administration_and_preserves_generation_and_home_bytes");
}

int main(int argc, char** argv) {
    CHECK(argc >= 4 && !getuid() && !geteuid() && !getegid());
    CHECK(strlen(argv[2]) < sizeof(root_path));
    strcpy(root_path, argv[2]);
    path(database, root_path, "db");
    path(records, root_path, "records");
    path(homes, root_path, "homes");
    accountctl = argv[3];
    if (!strcmp(argv[1], "prepare"))
        prepare();
    links();
    if (!strcmp(argv[1], "prepare")) {
        lookup("admin", 1000, 1000, "admin", secret, 0, 1);
        lookup("admin", 1000, 1000, "admin", secret, 1, 1);
        observed("actual_bootstrap_libc_lookup_password_and_primary_plus_sudo_groups");
    }
    if (!strcmp(argv[1], "exercise"))
        exercise();
    else if (!strcmp(argv[1], "concurrent"))
        concurrent();
    else if (!strcmp(argv[1], "verify"))
        verify();
    else if (!strcmp(argv[1], "attempt"))
        attempt();
    else if (!strcmp(argv[1], "recover"))
        recover();
    else if (!strcmp(argv[1], "full"))
        full_volume();
    else if (!strcmp(argv[1], "readonly"))
        readonly_volume();
    else
        CHECK(!strcmp(argv[1], "prepare"));
    if (strcmp(argv[1], "readonly"))
        inspect(argv[1]);
    printf("ACCOUNT_MANAGEMENT_EXT2_PASS phase=%s commands=%u observations=%u\n", argv[1], commands,
           observations);
    return 0;
}
