// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/ext2/journal.hpp
 * @brief   Ext2 recovery journal interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the journal records and operations used to stage and recover ext2
 * updates.
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

// Maximum number of home blocks that fit with descriptor and commit records.
unsigned journal_payload_limit(const Journal*);

// Scan the complete committed log before staging any home blocks. The caller
// validates the resulting filesystem overlay before checkpointing it to disk.
int journal_stage(Journal*, int (*stage)(void*, uint32_t, const void*), void*);

int journal_checkpoint(Journal*);

// Journal the complete operation, including data, before writing home blocks.
// On an I/O error the caller retains and retries the identical full operation.
int journal_commit(Journal*, const JournalWrite*, size_t count);
} // namespace ax
