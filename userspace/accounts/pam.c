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
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <string.h>
#include <unistd.h>

#define PAM_ENTRY __attribute__((visibility("default")))

static const char database_path[] = "/etc/axiom64/accounts";
static const char records_path[] = "/var/log/axiom64/login";
static const char profile_key[] = "axiom64.account.profile";
static const char record_line[] = "tty1";

static int root_helper(void) {
    return getuid() == 0 && geteuid() == 0 && getegid() == 0;
}

static void free_profile(pam_handle_t* handle, void* data, int status) {
    (void)handle;
    (void)status;
    account_profile_free(data);
}

static int failed_login(const char* name) {
    return account_recorded_deny(records_path, name, record_line) < 0 ? PAM_SYSTEM_ERR
                                                                      : PAM_AUTH_ERR;
}

static int check_profile(pam_handle_t* handle) {
    const void* data = NULL;
    const void* name = NULL;
    if (!root_helper() || pam_get_data(handle, profile_key, &data) != PAM_SUCCESS || !data ||
        pam_get_item(handle, PAM_USER, &name) != PAM_SUCCESS || !name)
        return PAM_PERM_DENIED;
    const struct account_profile* profile = data;
    if (strcmp(profile->name, name) != 0)
        return PAM_PERM_DENIED;

    struct account_database* database = NULL;
    if (account_database_begin(database_path, 0, &database) < 0)
        return PAM_AUTHINFO_UNAVAIL;
    const char* revision = account_database_revision(database);
    int current = revision && strcmp(revision, profile->revision) == 0;
    account_database_end(database);
    if (!current)
        return PAM_PERM_DENIED;

    if (profile->password_change_required) {
        pam_error(handle, "Change the password at the Axiom64 console before signing in.");
        return PAM_PERM_DENIED;
    }
    return PAM_SUCCESS;
}

PAM_ENTRY int pam_sm_authenticate(pam_handle_t* handle, int flags, int count,
                                  const char** options) {
    (void)flags;
    (void)count;
    (void)options;
    if (!root_helper())
        return PAM_PERM_DENIED;
    int result = pam_set_data(handle, profile_key, NULL, NULL);
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
        else
            result = pam_set_data(handle, profile_key, profile, free_profile);
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
    return check_profile(handle);
}

PAM_ENTRY int pam_sm_close_session(pam_handle_t* handle, int flags, int count,
                                   const char** options) {
    (void)handle;
    (void)flags;
    (void)count;
    (void)options;
    return root_helper() ? PAM_SUCCESS : PAM_PERM_DENIED;
}
