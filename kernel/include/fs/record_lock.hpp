// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "fs/vfs.hpp"

namespace ax {
struct Task;
struct FileTable;

struct RecordFlock {
    int16_t type, whence;
    uint32_t padding;
    int64_t start, length;
    int32_t pid;
    uint32_t padding2;
};

static_assert(sizeof(RecordFlock) == 32);

bool record_lock_command(uint64_t);
int record_lock_prepare(Handle*, unsigned command, RecordFlock&);
// Preparation captures an absolute range. Queries preserve unmodified caller
// fields when no conflict exists. Blocking setters retain a per-task wait and
// detect cycles among process-associated owners.
int record_lock_try(Task&, Handle*, unsigned command, RecordFlock&);
void record_lock_discard(Task&);
void record_lock_close(FileTable&, Node*);
void record_lock_release(FileTable&);
void record_lock_release(Handle&);
} // namespace ax
