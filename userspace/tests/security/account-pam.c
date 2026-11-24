/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * @file    userspace/tests/security/account-pam.c
 * @brief   Exercise the graphical account backend through Linux-PAM.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Run as root in a disposable guest or an isolated mount namespace.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include "../../accounts/database.h"
#include "../../accounts/guard.h"
#include "../../accounts/logbook.h"
#include "../../accounts/password.h"
#include <errno.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "ACCOUNT_PAM_FAIL line=%d condition=%s\n", __LINE__, #condition);      \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const char database[] = "/etc/axiom64/accounts";
static const char records[] = "/var/log/axiom64/login";
static const char secret[] = "Fixture-only-PAM-Authentication-42";

static int converse(int count, const struct pam_message** messages, struct pam_response** output,
                    void* data) {
    if (count != 1 ||
        (messages[0]->msg_style != PAM_PROMPT_ECHO_OFF && messages[0]->msg_style != PAM_ERROR_MSG))
        return PAM_CONV_ERR;
    struct pam_response* answer = calloc(1, sizeof(*answer));
    if (!answer)
        return PAM_BUF_ERR;
    if (messages[0]->msg_style == PAM_PROMPT_ECHO_OFF && !(answer->resp = strdup(data))) {
        free(answer);
        return PAM_BUF_ERR;
    }
    *output = answer;
    return PAM_SUCCESS;
}

static pam_handle_t* start_service(const char* service, const char* name, const char* password) {
    struct pam_conv conversation = {converse, (void*)password};
    pam_handle_t* handle = NULL;
    CHECK(pam_start(service, name, &conversation, &handle) == PAM_SUCCESS);
    return handle;
}

static pam_handle_t* start(const char* name, const char* password) {
    return start_service("axiom64-test", name, password);
}

static void account_state(int create, int expired) {
    struct account_database* db = NULL;
    CHECK(account_database_begin(database, create, &db) == 0);
    if (create) {
        const struct account_group group = {"alice", 1000, NULL, 0};
        CHECK(account_database_put_group(db, NULL, &group) == 0);
    }
    char hash[ACCOUNT_PASSWORD_HASH_SIZE];
    CHECK(account_password_hash(secret, hash) == 0);
    const int64_t today = (int64_t)time(NULL) / 86400;
    const struct account_user user = {
        "alice", hash, expired ? "Expired fixture" : "Alice fixture", "/home/alice", "/bin/sh",
        1000,    1000, {expired ? 0 : today, 0, -1, -1, -1, -1},
    };
    CHECK(account_database_put_user(db, create ? NULL : "alice", &user) == 0);
    int published;
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
    account_password_clear(hash, sizeof(hash));
}

static void denied(const char* name, const char* password) {
    pam_handle_t* handle = start(name, password);
    const int result = pam_authenticate(handle, 0);
    const int account = pam_acct_mgmt(handle, 0);
    if (result != PAM_AUTH_ERR || account != PAM_PERM_DENIED)
        fprintf(stderr, "PAM denial for %s returned auth=%d account=%d\n", name, result, account);
    CHECK(result == PAM_AUTH_ERR && account == PAM_PERM_DENIED);
    CHECK(pam_end(handle, result) == PAM_SUCCESS);
}

static void session_active(int active) {
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(records, 0, &book) == 0);
    CHECK(account_logbook_active(book, 1000) == active);
    int status = account_guard_new_ids(book, 1000, (gid_t)-1);
    CHECK(active ? status < 0 && errno == EBUSY : status == 0);
    account_logbook_close(book);
}

static void wait_child(pid_t child) {
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void verify_helper_cleanup(void) {
    pam_handle_t* handle = start("alice", secret);
    CHECK(pam_authenticate(handle, 0) == PAM_SUCCESS && pam_open_session(handle, 0) == PAM_SUCCESS);
    session_active(1);
    CHECK(pam_open_session(handle, 0) == PAM_SESSION_ERR);
    CHECK(pam_authenticate(handle, 0) == PAM_SESSION_ERR);
    session_active(1);
    CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
    session_active(0);

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        pam_handle_t* interrupted = start("alice", secret);
        CHECK(pam_authenticate(interrupted, 0) == PAM_SUCCESS);
        CHECK(pam_open_session(interrupted, 0) == PAM_SUCCESS);
        _exit(0);
    }
    wait_child(child);
    session_active(0);
    puts("ACCOUNT_PAM_RECOVERED_SUPERVISOR_LEASE");
}

static void verify_policykit_helper(void) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setresgid(1000, 1000, 0) == 0 && setresuid(1000, 0, 0) == 0);
        pam_handle_t* handle = start_service("polkit-1", "alice", secret);
        CHECK(pam_authenticate(handle, 0) == PAM_PERM_DENIED);
        CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
        CHECK(setegid(0) == 0);
        handle = start("alice", secret);
        CHECK(pam_authenticate(handle, 0) == PAM_PERM_DENIED);
        CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
        handle = start_service("polkit-1", "alice", secret);
        CHECK(pam_acct_mgmt(handle, 0) == PAM_PERM_DENIED);
        CHECK(pam_authenticate(handle, 0) == PAM_SUCCESS);
        CHECK(pam_acct_mgmt(handle, 0) == PAM_SUCCESS);
        CHECK(pam_setcred(handle, PAM_ESTABLISH_CRED) == PAM_PERM_DENIED);
        CHECK(getuid() == 1000 && getgid() == 1000 && geteuid() == 0 && getegid() == 0);
        CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
        _exit(0);
    }
    wait_child(child);
    session_active(0);
    puts("ACCOUNT_PAM_VERIFIED_POLICYKIT_HELPER");
}

int main(void) {
    CHECK(getuid() == 0 && access("/etc/pam.d/axiom64-test", R_OK) == 0);
    CHECK(access(database, F_OK) != 0);
    account_state(1, 0);
    denied("alice", "wrong");
    denied("missing", secret);
    denied("root", secret);
    denied("alice", "");
    denied("bad/name", secret);
    puts("ACCOUNT_PAM_DENIED_PASSWORD_AND_ACCOUNT");

    pam_handle_t* handle = start("alice", secret);
    CHECK(pam_acct_mgmt(handle, 0) == PAM_PERM_DENIED);
    CHECK(pam_authenticate(handle, 0) == PAM_SUCCESS && pam_acct_mgmt(handle, 0) == PAM_SUCCESS);
    CHECK(pam_setcred(handle, PAM_ESTABLISH_CRED) == PAM_SUCCESS);
    CHECK(pam_open_session(handle, 0) == PAM_SUCCESS);
    session_active(1);
    pid_t inherited = fork();
    CHECK(inherited >= 0);
    if (!inherited) {
        CHECK(pam_close_session(handle, 0) == PAM_PERM_DENIED);
        CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
        _exit(0);
    }
    wait_child(inherited);
    session_active(1);
    CHECK(pam_close_session(handle, 0) == PAM_SUCCESS);
    session_active(0);
    CHECK(pam_setcred(handle, PAM_DELETE_CRED) == PAM_SUCCESS);
    CHECK(pam_set_item(handle, PAM_USER, "root") == PAM_SUCCESS);
    CHECK(pam_acct_mgmt(handle, 0) == PAM_PERM_DENIED);
    CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
    puts("ACCOUNT_PAM_VERIFIED_CREDENTIAL_AND_REJECTED_IDENTITY_CHANGE");
    verify_helper_cleanup();
    verify_policykit_helper();

    handle = start("alice", secret);
    CHECK(pam_authenticate(handle, 0) == PAM_SUCCESS);
    account_state(0, 1);
    CHECK(pam_setcred(handle, PAM_ESTABLISH_CRED) == PAM_PERM_DENIED);
    CHECK(pam_open_session(handle, 0) == PAM_PERM_DENIED);
    CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
    handle = start("alice", secret);
    CHECK(pam_authenticate(handle, 0) == PAM_SUCCESS &&
          pam_acct_mgmt(handle, 0) == PAM_PERM_DENIED);
    CHECK(pam_end(handle, PAM_SUCCESS) == PAM_SUCCESS);
    puts("ACCOUNT_PAM_REJECTED_STALE_AND_PASSWORD_CHANGE_REQUIRED");

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgid(1000) == 0 && setuid(1000) == 0);
        pam_handle_t* own = start("alice", secret);
        CHECK(pam_authenticate(own, 0) == PAM_PERM_DENIED);
        CHECK(pam_end(own, PAM_SUCCESS) == PAM_SUCCESS);
        _exit(0);
    }
    wait_child(child);
    puts("ACCOUNT_PAM_REJECTED_UNPRIVILEGED_CALLER");
    return 0;
}
