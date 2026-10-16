// SPDX-License-Identifier: GPL-3.0-or-later
#include "abi/linux/eventfd.hpp"
#include "fs/descriptor.hpp"
#include "ipc/eventfd.hpp"
#include "process/task.hpp"

namespace ax {
int64_t eventfd_syscall(const Frame& frame) {
    uint32_t flags = frame.rax == 290 ? uint32_t(frame.rsi) : 0;
    if (flags & ~uint32_t(1 | 04000 | 02000000))
        return -22;
    int fd = reserve_fd(*current, 0, flags & 02000000);
    if (fd < 0)
        return fd;
    int error;
    auto handle = open_eventfd(uint32_t(frame.rdi), flags & 1, flags & 04000, error);
    if (!handle) {
        discard_reserved_fd(*current->files, fd);
        return error;
    }
    install_reserved_fd(*current->files, fd, handle);
    return fd;
}
} // namespace ax
