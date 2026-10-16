// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax {
struct Journal;

// The filesystem validates the immutable journal inode/map and claims the disk.
// Transfers address physical filesystem blocks; successful flushes are durable.
struct JournalStorage {
    void* context;
    uint32_t block_size, volume_blocks;
    const uint32_t* blocks;
    uint32_t count;
    int (*read)(void*, uint32_t, void*);
    int (*write)(void*, uint32_t, const void*);
    int (*flush)(void*);
};

struct JournalWrite {
    uint32_t block;
    const void* data;
};

Journal* journal_open(const JournalStorage&, const uint8_t uuid[16], int& error);

void journal_close(Journal*);

bool journal_pending(const Journal*);

// Scan the complete committed log before staging any home blocks. The caller
// validates the resulting filesystem overlay before checkpointing it to disk.
int journal_stage(Journal*, int (*stage)(void*, uint32_t, const void*), void*);

int journal_checkpoint(Journal*);

// Journal the complete operation, including data, before writing home blocks.
// On an I/O error the caller retains and retries the identical full operation.
int journal_commit(Journal*, const JournalWrite*, size_t count);
} // namespace ax
