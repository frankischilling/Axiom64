// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_BUSY_H
#define AXIOM64_ACCOUNTS_BUSY_H
#include <sys/types.h>

// One means a process/thread retains any requested real/effective/saved/fs ID
// or supplementary GID. UINT32_MAX skips that identity dimension. Zero means
// the complete live procfs scan found none; failures never mean safe to reuse.
int account_process_busy(uid_t, gid_t);

#endif
