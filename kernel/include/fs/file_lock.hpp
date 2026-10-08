// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "fs/vfs.hpp"

namespace ax {
// Serialized by the current single-CPU syscall/scheduler execution model.
// Locks belong to descriptions, use canonical nodes, and remain advisory.
bool file_lock_operation(uint32_t);

int file_lock_try(Handle*, uint32_t);

void file_lock_release(Handle*);
} // namespace ax
