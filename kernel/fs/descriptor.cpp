// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/descriptor.hpp"
#include "process/task.hpp"
#include "fs/record_lock.hpp"

namespace ax {
int reserve_fd(Task& task, int start, bool cloexec) {
    if (start < 0)
        return -22;
    auto& table = *task.files;
    uint64_t limit = task.process->limits.soft(Resource::open_files);
    for (unsigned index = start; index < max_fds && index < limit; index++)
        if (!table.entries[index].handle && !table.entries[index].reserved) {
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
        if (!(handle->flags & 010000000))
            record_lock_close(table, handle->node);
        close_handle(handle);
    }
    table.entries[fd] = {};
}
} // namespace ax
