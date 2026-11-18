// SPDX-License-Identifier: GPL-3.0-or-later
#include "abi/linux/signalfd.hpp"
#include "fs/descriptor.hpp"
#include "ipc/ipc.hpp"
#include "ipc/signal_descriptor.hpp"
#include "process/signals.hpp"

namespace ax {
int64_t signalfd_syscall(const Frame& frame) {
    uint64_t mask;
    if (frame.rdx != sizeof(mask))
        return -22;
    if (!current->memory->space.copy_in(&mask, frame.rsi, sizeof(mask)))
        return -14;
    uint32_t flags = frame.rax == 289 ? uint32_t(frame.r10) : 0;
    constexpr uint32_t nonblocking = 04000;
    constexpr uint32_t close_on_exec = 02000000;
    if (flags & ~(nonblocking | close_on_exec))
        return -22;
    mask &= ~unmaskable_signals;
    int fd = int(frame.rdi);
    if (fd != -1) {
        auto handle = unsigned(fd) < max_fds ? current->files->entries[fd].handle : nullptr;
        if (!handle)
            return -9;
        if (!handle->signal_descriptor)
            return -22;
        handle->signal_descriptor->mask = mask;
        epoll_signal_notify(*current->handlers);
        return fd;
    }
    fd = reserve_fd(*current, 0, flags & close_on_exec);
    if (fd < 0)
        return fd;
    int error;
    auto handle = open_signal_descriptor(mask, flags & nonblocking, error);
    if (!handle) {
        discard_reserved_fd(*current->files, fd);
        return error;
    }
    install_reserved_fd(*current->files, fd, handle);
    return fd;
}
} // namespace ax
