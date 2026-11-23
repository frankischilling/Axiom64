/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * @file    userspace/accounts/pam.c
 * @brief   Authenticate a graphical login through the Axiom64 account store.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Keeps the verified account generation on the PAM handle and checks it
 * again before credentials are established or a session is opened.
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

#define _POSIX_C_SOURCE 200809L
#include "auth.h"
#include "database.h"
#include "password.h"
#include "recorded.h"
#include <errno.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAM_ENTRY __attribute__((visibility("default")))

static const char database_path[] = "/etc/axiom64/accounts";
static const char records_path[] = "/var/log/axiom64/login";
static const char login_key[] = "axiom64.account.login";
static const char record_line[] = "tty1";

struct pam_login {
    struct account_profile* profile;
    struct account_recorded_session session;
    pid_t owner;
};

static int root_helper(void) {
    return getuid() == 0 && geteuid() == 0 && getegid() == 0;
}

static void free_login(pam_handle_t* handle, void* data, int status) {
    (void)handle;
    (void)status;
    struct pam_login* login = data;
    if (login->owner == getpid() && login->session.lease)
        account_recorded_end(&login->session, 0, ECANCELED);
    account_profile_free(login->profile);
    free(login);
}

static int failed_login(const char* name) {
    return account_recorded_deny(records_path, name, record_line) < 0 ? PAM_SYSTEM_ERR
                                                                      : PAM_AUTH_ERR;
}

static struct pam_login* get_login(pam_handle_t* handle) {
    const void* data = NULL;
    if (!root_helper() || pam_get_data(handle, login_key, &data) != PAM_SUCCESS || !data)
        return NULL;
    struct pam_login* login = (struct pam_login*)data;
    return login->owner == getpid() ? login : NULL;
}

static int check_user(pam_handle_t* handle, const struct pam_login* login) {
    const void* name = NULL;
    if (!login || pam_get_item(handle, PAM_USER, &name) != PAM_SUCCESS || !name ||
        strcmp(login->profile->name, name) != 0)
        return PAM_PERM_DENIED;
    if (login->profile->password_change_required) {
        pam_error(handle, "Change the password at the Axiom64 console before signing in.");
        return PAM_PERM_DENIED;
    }
    return PAM_SUCCESS;
}

static int check_profile(pam_handle_t* handle) {
    struct pam_login* login = get_login(handle);
    int result = check_user(handle, login);
    if (result != PAM_SUCCESS)
        return result;
    struct account_database* database = NULL;
    if (account_database_begin(database_path, 0, &database) < 0)
        return PAM_AUTHINFO_UNAVAIL;
    const char* revision = account_database_revision(database);
    int current = revision && strcmp(revision, login->profile->revision) == 0;
    account_database_end(database);
    return current ? PAM_SUCCESS : PAM_PERM_DENIED;
}

PAM_ENTRY int pam_sm_authenticate(pam_handle_t* handle, int flags, int count,
                                  const char** options) {
    (void)flags;
    (void)count;
    (void)options;
    if (!root_helper())
        return PAM_PERM_DENIED;
    struct pam_login* previous = get_login(handle);
    if (previous && previous->session.lease)
        return PAM_SESSION_ERR;
    int result = pam_set_data(handle, login_key, NULL, NULL);
    if (result != PAM_SUCCESS)
        return result;

    const char* name = NULL;
    result = pam_get_user(handle, &name, NULL);
    if (result != PAM_SUCCESS)
        return result;
    if (!name || !account_name_valid(name))
        return failed_login(name ? name : "");

    const char* secret = NULL;
    result = pam_get_authtok(handle, PAM_AUTHTOK, &secret, NULL);
    if (result != PAM_SUCCESS)
        return result;
    struct account_profile* profile = NULL;
    int auth_result = ACCOUNT_AUTH_DENIED;
    if (secret && *secret && strnlen(secret, ACCOUNT_PASSWORD_MAX + 1) <= ACCOUNT_PASSWORD_MAX)
        auth_result = account_auth_password(database_path, name, secret, 0, &profile);
    result = pam_set_item(handle, PAM_AUTHTOK, NULL);
    if (result == PAM_SUCCESS) {
        if (auth_result < 0)
            result = PAM_AUTHINFO_UNAVAIL;
        else if (!profile || !profile->uid)
            result = failed_login(name);
        else {
            struct pam_login* login = calloc(1, sizeof(*login));
            if (!login)
                result = PAM_BUF_ERR;
            else {
                login->profile = profile;
                login->session = (struct account_recorded_session){
                    .database = database_path,
                    .records = records_path,
                    .target = profile,
                    .operation = ACCOUNT_LOGIN_START,
                    .actor = profile->uid,
                };
                login->owner = getpid();
                result = pam_set_data(handle, login_key, login, free_login);
                if (result != PAM_SUCCESS)
                    free(login);
            }
        }
    }
    if (result != PAM_SUCCESS)
        account_profile_free(profile);
    return result;
}

PAM_ENTRY int pam_sm_acct_mgmt(pam_handle_t* handle, int flags, int count, const char** options) {
    (void)flags;
    (void)count;
    (void)options;
    return check_profile(handle);
}

PAM_ENTRY int pam_sm_setcred(pam_handle_t* handle, int flags, int count, const char** options) {
    (void)count;
    (void)options;
    if (flags & PAM_DELETE_CRED)
        return root_helper() ? PAM_SUCCESS : PAM_PERM_DENIED;
    return check_profile(handle);
}

PAM_ENTRY int pam_sm_open_session(pam_handle_t* handle, int flags, int count,
                                  const char** options) {
    (void)flags;
    (void)count;
    (void)options;
    struct pam_login* login = get_login(handle);
    int result = check_user(handle, login);
    if (result != PAM_SUCCESS)
        return result;
    if (login->session.lease)
        return PAM_SESSION_ERR;
    if (account_recorded_begin_supervised(&login->session, record_line) == 0)
        return PAM_SUCCESS;
    int error = errno;
    account_recorded_end(&login->session, 0, ECANCELED);
    return error == ESTALE ? PAM_PERM_DENIED : PAM_SESSION_ERR;
}

PAM_ENTRY int pam_sm_close_session(pam_handle_t* handle, int flags, int count,
                                   const char** options) {
    (void)flags;
    (void)count;
    (void)options;
    struct pam_login* login = get_login(handle);
    if (!login)
        return PAM_PERM_DENIED;
    return account_recorded_end(&login->session, 0, 0) == 0 ? PAM_SUCCESS : PAM_SESSION_ERR;
}
