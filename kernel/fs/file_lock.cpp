// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/file_lock.hpp"

namespace ax {
bool file_lock_operation(uint32_t operation) {
    uint32_t kind = operation & ~uint32_t(4);
    return kind == 1 || kind == 2 || kind == 8;
}

void file_lock_release(Handle* handle) {
    if (!handle || !handle->file_lock)
        return;
    auto node = handle->node;
    if (handle->file_lock == 1)
        --node->lock_readers;
    else
        node->lock_writer = nullptr;
    handle->file_lock = 0;
}

int file_lock_try(Handle* handle, uint32_t operation) {
    if (!file_lock_operation(operation))
        return -22;
    if (!handle || (handle->flags & 010000000)) // O_PATH does not allow flock.
        return -9;
    auto node = handle->node;
    if (!node)
        return -95;
    unsigned kind = operation & ~uint32_t(4);
    if (kind == handle->file_lock)
        return 0;
    // Linux conversions release the previous mode even if acquisition fails.
    file_lock_release(handle);
    if (kind == 8)
        return 0;
    if (node->lock_writer || (kind == 2 && node->lock_readers))
        return -11;
    if (kind == 1)
        ++node->lock_readers;
    else
        node->lock_writer = handle;
    handle->file_lock = kind;
    return 0;
}
} // namespace ax
