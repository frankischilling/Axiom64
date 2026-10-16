// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_LOGIN_RECORD_H
#define AXIOM64_ACCOUNTS_LOGIN_RECORD_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum account_login_kind {
    ACCOUNT_LOGIN_START = 1,
    ACCOUNT_LOGIN_END,
    ACCOUNT_LOGIN_DENIED,
    ACCOUNT_LOGIN_SU,
    ACCOUNT_LOGIN_SUDO,
    ACCOUNT_LOGIN_PASSWORD,
    ACCOUNT_LOGIN_ADMIN,
    ACCOUNT_LOGIN_BOOT,
    ACCOUNT_LOGIN_RECOVERED,
    ACCOUNT_LOGIN_USER_ADD,
    ACCOUNT_LOGIN_USER_DELETE,
    ACCOUNT_LOGIN_USER_RENAME,
    ACCOUNT_LOGIN_USER_HOME,
    ACCOUNT_LOGIN_USER_SHELL,
    ACCOUNT_LOGIN_GROUP_ADD,
    ACCOUNT_LOGIN_GROUP_DELETE,
    ACCOUNT_LOGIN_GROUP_RENAME,
    ACCOUNT_LOGIN_MEMBER_ADD,
    ACCOUNT_LOGIN_MEMBER_DELETE,
    ACCOUNT_LOGIN_LOCK,
    ACCOUNT_LOGIN_UNLOCK,
    ACCOUNT_LOGIN_BOOTSTRAP
};

// Linux x86-64's 384-byte utmp ABI uses 32-bit session and timeval fields,
// independently of the target libc's time_t and internal utmp declarations.
struct account_login_entry {
    int16_t type, padding;
    int32_t pid;
    char line[32], id[4], user[32], host[256];
    int16_t termination, exit_code;
    int32_t session, seconds, microseconds;
    uint32_t address[4];
    unsigned char unused[20];
};

// The private journal retains full-width time/identities and a unique lease
// token. CRC protects accidental corruption; ownership protects authorization.
struct account_login_frame {
    uint32_t magic, version, size, crc;
    uint64_t sequence;
    int64_t seconds;
    struct account_login_entry entry;
    uint32_t uid, gid, kind;
    int32_t status;
    unsigned char token[16];
};

_Static_assert(sizeof(struct account_login_entry) == 384, "Linux utmp wire size");
_Static_assert(offsetof(struct account_login_entry, session) == 336, "Linux utmp session offset");
_Static_assert(offsetof(struct account_login_entry, seconds) == 340, "Linux utmp timeval offset");
_Static_assert(sizeof(struct account_login_frame) == 448, "Version-one login journal frame");

int account_login_frame_make(struct account_login_frame*, enum account_login_kind, const char* name,
                             uid_t, gid_t, pid_t, const char* terminal, const char* target,
                             int status, const unsigned char token[16]);
void account_login_frame_seal(struct account_login_frame*, uint64_t sequence);
int account_login_frame_valid(const struct account_login_frame*, uint64_t sequence);
const char* account_login_kind_name(enum account_login_kind);
int account_login_terminal(const char* input, char output[32]);

#endif
