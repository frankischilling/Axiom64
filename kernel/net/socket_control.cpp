// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/socket_control.hpp"
#include "process/task.hpp"

namespace ax {
void SocketControlWriter::append(uint32_t type, const void* bytes, size_t size) {
    if (!address || capacity < 16) {
        flags |= 8;
        return;
    }
    uint64_t length = min(capacity, uint64_t(16 + size));
    if (length < 16 + size)
        flags |= 8;
    if (address >= user_limit || length > user_limit - address)
        return;
    // A failed control copy leaves its written prefix visible. It consumes
    // no capacity, so later enabled controls still try the same position.
    if (!task.memory->space.copy_out(address, &length, 8) ||
        !task.memory->space.copy_out(address + 8, &level, 4) ||
        !task.memory->space.copy_out(address + 12, &type, 4))
        return;
    auto source = static_cast<const uint8_t*>(bytes);
    size_t remaining = length - 16;
    uint64_t at = address + 16;
    while (remaining) {
        // Linux x86-64 control copies commit complete 8/4/2/1-byte stores.
        size_t copied = remaining >= 8 ? 8 : remaining >= 4 ? 4 : remaining >= 2 ? 2 : 1;
        if (!task.memory->space.copy_out(at, source, copied))
            return;
        at += copied;
        source += copied;
        remaining -= copied;
    }
    // Account for alignment without writing padding bytes.
    uint64_t consumed = min(capacity, uint64_t((16 + size + 7) & ~size_t(7)));
    used += consumed;
    address += consumed;
    capacity -= consumed;
}
} // namespace ax
