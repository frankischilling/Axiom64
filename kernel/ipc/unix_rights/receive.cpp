// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/unix_rights.hpp"
#include "fs/descriptor.hpp"
#include "process/task.hpp"

namespace ax {
size_t UnixRights::write(Task& task, uint64_t pointer, size_t capacity, bool cloexec,
                         uint32_t& flags) const {
    unsigned installed = 0;
    unsigned available = capacity > 16 ? min(size_t(count), (capacity - 16) / 4) : 0;
    if (!pointer)
        available = 0;
    for (; installed < available; installed++) {
        int fd = reserve_fd(task, 0, cloexec);
        if (fd < 0)
            break;
        uint64_t offset = 16 + size_t(installed) * 4;
        if (pointer >= user_limit || offset > user_limit - pointer ||
            !task.memory->space.copy_out(pointer + offset, &fd, 4)) {
            discard_reserved_fd(*task.files, fd);
            break;
        }
        retain(files[installed]);
        install_reserved_fd(*task.files, fd, files[installed]);
    }
    size_t used = 0;
    if (installed) {
        uint64_t length = 16 + size_t(installed) * 4;
        int level = 1, type = 1;
        // Installed descriptors survive a later header fault, matching the
        // receive order. A failing descriptor-number copy never installs it.
        if (task.memory->space.copy_out(pointer + 8, &level, 4) &&
            task.memory->space.copy_out(pointer + 12, &type, 4) &&
            task.memory->space.copy_out(pointer, &length, 8))
            used = min(capacity, size_t((length + 7) & ~uint64_t(7)));
    }
    if (installed < count)
        flags |= 8;
    return used;
}
} // namespace ax
