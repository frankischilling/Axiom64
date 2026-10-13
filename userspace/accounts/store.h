// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_STORE_H
#define AXIOM64_ACCOUNTS_STORE_H

#include <stddef.h>
#include <sys/types.h>

enum account_file { ACCOUNT_PASSWD, ACCOUNT_GROUP, ACCOUNT_SHADOW, ACCOUNT_FILE_COUNT };

#define ACCOUNT_FILE_LIMIT (1024 * 1024)

struct account_content {
    const char* data;
    size_t size;
};
struct account_store;

// A transaction requires effective UID/GID zero. It validates the entire path,
// holds an exclusive process lock, and reads one complete immutable generation.
// Only explicit provisioning may create a missing store/current generation.
int account_store_begin(const char* path, int provision, struct account_store**);
// NULL means an unprovisioned store; otherwise exactly ACCOUNT_FILE_COUNT entries.
// The returned bytes remain owned by the transaction until account_store_end.
const struct account_content* account_store_snapshot(const struct account_store*);
// Public generation identity, not password data. NULL means unprovisioned.
const char* account_store_revision(const struct account_store*);
// A validated unpublished home intent can block rollback while the preceding
// complete generation remains readable. Commits reject this recovery error.
int account_store_recovery_error(const struct account_store*);
// One commit attempt per transaction. All three files must be complete text.
// On failure, published confirms a visible complete update whose durability or
// cleanup did not finish. If namespace inspection itself fails, preserve the
// planned state for recovery; a zero result never authorizes assumed rollback.
int account_store_commit(struct account_store*, const struct account_content[ACCOUNT_FILE_COUNT],
                         int* published);
// Coordinate a new private home with the same immutable generation. The store
// persists its protected intent before creation and recovers it on locked open.
int account_store_commit_home(struct account_store*,
                              const struct account_content[ACCOUNT_FILE_COUNT], const char* home,
                              uid_t, gid_t, int* published);
void account_store_end(struct account_store*);

#endif
