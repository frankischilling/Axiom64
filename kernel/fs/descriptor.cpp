// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/descriptor.cpp
 * @brief   File descriptor tables.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Allocates descriptors, tracks close-on-exec flags, and maintains references
 * during duplication and release.
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
#include "fs/descriptor.hpp"
#include "process/task.hpp"
#include "fs/record_lock.hpp"
#include "ipc/posix_message_queues.hpp"

namespace ax {
int reserve_fd(Task& task, int start, bool cloexec) {
    if (start < 0)
        return -22;
    auto& table = *task.files;
    uint64_t limit = task.process->limits.soft(Resource::open_files);
    for (unsigned index = start; index < max_fds && index < limit; index++)
        if (!table.entries[index].handle && !table.entries[index].reserved) {
            table.expand(index);
            table.entries[index] = {nullptr, cloexec, true};
            return index;
        }
    return -24;
}

void install_reserved_fd(FileTable& table, int fd, Handle* handle) {
    if (fd < 0 || unsigned(fd) >= max_fds || !handle || !table.entries[fd].reserved ||
        table.entries[fd].handle)
        panic("invalid file descriptor installation");
    table.entries[fd].handle = handle;
    table.entries[fd].reserved = false;
}

void discard_reserved_fd(FileTable& table, int fd) {
    if (fd >= 0 && unsigned(fd) < max_fds && table.entries[fd].reserved)
        table.entries[fd] = {};
}

int allocate_fd(Task* task, Handle* handle, int start, bool cloexec) {
    int fd = reserve_fd(*task, start, cloexec);
    if (fd >= 0)
        install_reserved_fd(*task->files, fd, handle);
    return fd;
}

void close_descriptor(FileTable& table, int fd) {
    if (fd < 0 || unsigned(fd) >= max_fds)
        return;
    auto handle = table.entries[fd].handle;
    if (handle) {
        posix_queue_descriptor_closed(handle);
        if (!(handle->flags & 010000000))
            record_lock_close(table, handle->node);
        close_handle(handle);
    }
    table.entries[fd] = {};
}
} // namespace ax
