// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/descriptor.hpp"
#include "process/task.hpp"

namespace ax {
int reserve_fd(FileTable& table, int start, bool cloexec) {
    if (start < 0)
        return -22;
    for (unsigned index = start; index < max_fds; index++)
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
    int fd = reserve_fd(*task->files, start, cloexec);
    if (fd >= 0)
        install_reserved_fd(*task->files, fd, handle);
    return fd;
}
} // namespace ax
