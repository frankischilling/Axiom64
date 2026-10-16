// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/auth.h"
#include "../../accounts/database.h"
#include "../../accounts/update.h"
#include <errno.h>
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
            fprintf(stderr, "ACCOUNT_UPDATE_FAIL line=%d errno=%d expression=%s\n", __LINE__,      \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static char database[4096], records[4096], home[4096];
static unsigned observations;
static const char *first = "Fixture-update-old-83", *second = "Fixture-update-new-94";

static void observed(const char* name) {
    printf("ACCOUNT_UPDATE_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static struct account_profile* authenticate(const char* password, int result) {
    struct account_profile* profile = NULL;
    CHECK(account_auth_password(database, "admin", password, 0, &profile) == result);
    return profile;
}

static void age(int64_t last, int64_t minimum) {
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, 0, &db) == 0);
    struct account_user changed = *account_database_user(db, "admin");
    if (last >= 0)
        changed.age[0] = last;
    changed.age[1] = minimum;
    CHECK(account_database_put_user(db, "admin", &changed) == 0);
    int published;
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
}

static void bootstrap_busy_identity(void) {
    int published;
    int started[2], finish[2];
    CHECK(pipe(started) == 0 && pipe(finish) == 0);
    pid_t service = fork();
    CHECK(service >= 0);
    if (!service) {
        close(started[0]);
        close(finish[1]);
        CHECK(setgroups(0, NULL) == 0 && setresgid(1000, 1000, 1000) == 0 &&
              setresuid(1000, 1000, 1000) == 0);
        char byte = 'x';
        CHECK(write(started[1], &byte, 1) == 1 && read(finish[0], &byte, 1) == 1);
        _exit(0);
    }
    close(started[1]);
    close(finish[0]);
    char byte;
    CHECK(read(started[0], &byte, 1) == 1);
    CHECK(account_bootstrap(database, records, "admin", home, "/bin/sh", first, &published) == -1 &&
          errno == EBUSY && !published);
    struct stat untouched_home;
    CHECK(stat(home, &untouched_home) == -1 && errno == ENOENT);
    CHECK(write(finish[1], &byte, 1) == 1);
    int service_status;
    CHECK(waitpid(service, &service_status, 0) == service && WIFEXITED(service_status) &&
          !WEXITSTATUS(service_status));
    close(started[0]);
    close(finish[1]);
    observed("first_administrator_ids_in_use_deny_bootstrap_without_publication_or_home");
}

int main(int argc, char** argv) {
    CHECK(argc == 2 && !getuid() && !geteuid() && !getegid());
    CHECK(mkdir(argv[1], 0755) == 0 && chmod(argv[1], 0755) == 0);
    CHECK(snprintf(database, sizeof(database), "%s/db", argv[1]) < (int)sizeof(database));
    CHECK(snprintf(records, sizeof(records), "%s/records", argv[1]) < (int)sizeof(records));
    CHECK(snprintf(home, sizeof(home), "%s/admin", argv[1]) < (int)sizeof(home));
    bootstrap_busy_identity();
    int published;
    CHECK(account_bootstrap(database, records, "admin", home, "/bin/sh", first, &published) == 0 &&
          published);
    CHECK(account_bootstrap(database, records, "admin", home, "/bin/sh", first, &published) == -1 &&
          errno == EEXIST && !published);
    observed("complete_bootstrap_and_existing_store_denial");
    struct account_profile* profile = authenticate(first, ACCOUNT_AUTH_ACCEPTED);
    struct account_profile impostor = *profile;
    impostor.uid = 1001;
    CHECK(account_password_update(database, records, profile, &impostor, second, &published) ==
              -1 &&
          errno == EACCES && !published);
    observed("different_authenticated_identity_cannot_change_target_password");
    CHECK(account_password_update(database, records, profile, profile, second, &published) == 0 &&
          published);
    CHECK(account_password_update(database, records, profile, profile, first, &published) == -1 &&
          errno == ESTALE && !published);
    account_profile_free(profile);
    CHECK(!authenticate(first, ACCOUNT_AUTH_DENIED));
    profile = authenticate(second, ACCOUNT_AUTH_ACCEPTED);
    account_profile_free(profile);
    observed("owned_update_invalidates_old_profile_and_rejects_stale_revision");
    age(-1, 1);
    profile = authenticate(second, ACCOUNT_AUTH_ACCEPTED);
    CHECK(account_password_update(database, records, profile, profile, first, &published) == -1 &&
          errno == EACCES && !published);
    account_profile_free(profile);
    observed("minimum_age_denial_preserves_existing_password");
    age(0, 1);
    profile = authenticate(second, ACCOUNT_AUTH_CHANGE_REQUIRED);
    CHECK(profile->password_change_required);
    CHECK(account_password_update(database, records, profile, profile, first, &published) == 0 &&
          published);
    account_profile_free(profile);
    profile = authenticate(first, ACCOUNT_AUTH_ACCEPTED);
    account_profile_free(profile);
    observed("forced_change_completes_then_requires_fresh_authentication");
    age(-1, 0);
    profile = authenticate(first, ACCOUNT_AUTH_ACCEPTED);
    int result[2];
    CHECK(pipe(result) == 0);
    pid_t children[2];
    const char* passwords[] = {second, "Fixture-update-concurrent-05"};
    for (unsigned i = 0; i < 2; i++) {
        children[i] = fork();
        CHECK(children[i] >= 0);
        if (!children[i]) {
            close(result[0]);
            int visible = 0;
            int value = account_password_update(database, records, profile, profile, passwords[i],
                                                &visible);
            int row[] = {(int)i, value, visible, value < 0 ? errno : 0};
            CHECK(write(result[1], row, sizeof(row)) == (ssize_t)sizeof(row));
            account_profile_free(profile);
            exit(0);
        }
    }
    close(result[1]);
    unsigned successes = 0, denied = 0, winner = 2;
    for (unsigned i = 0; i < 2; i++) {
        int row[4];
        CHECK(read(result[0], row, sizeof(row)) == (ssize_t)sizeof(row));
        CHECK(row[0] == 0 || row[0] == 1);
        if (!row[1]) {
            CHECK(row[2] == 1 && !row[3]);
            successes++;
            winner = (unsigned)row[0];
        } else {
            CHECK(row[1] == -1 && !row[2] && row[3] == ESTALE);
            denied++;
        }
        int status;
        CHECK(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) &&
              !WEXITSTATUS(status));
    }
    close(result[0]);
    CHECK(successes == 1 && denied == 1 && winner < 2);
    account_profile_free(profile);
    profile = authenticate(passwords[winner], ACCOUNT_AUTH_ACCEPTED);
    account_profile_free(profile);
    CHECK(!authenticate(passwords[1 - winner], ACCOUNT_AUTH_DENIED));
    observed("two_concurrent_authenticated_updates_publish_exactly_one_generation");
    printf("ACCOUNT_UPDATE_PASS observations=%u\n", observations);
    return 0;
}
