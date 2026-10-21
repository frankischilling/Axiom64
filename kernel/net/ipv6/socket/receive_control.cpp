// SPDX-License-Identifier: GPL-3.0-or-later
#include "../socket.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
class ControlWriter {
  public:
    ControlWriter(Task& owner, uint64_t pointer, uint64_t limit, uint32_t& result)
        : task(owner), address(pointer), capacity(limit), flags(result) {
    }

    void append(uint32_t type, const void* bytes, size_t size) {
        if (!address || capacity < 16) {
            flags |= 8;
            return;
        }
        uint64_t length = min(capacity, uint64_t(16 + size));
        if (length < 16 + size)
            flags |= 8;
        if (address >= user_limit || length > user_limit - address)
            return;
        uint32_t level = 41;
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

    uint64_t used = 0;

  private:
    Task& task;
    uint64_t address, capacity;
    uint32_t& flags;
};
} // namespace

size_t inet6_receive_control(Task& task, Inet6Socket* socket, const Inet6Frame& frame,
                             uint64_t address, uint64_t capacity, uint32_t& flags) {
    ControlWriter output(task, address, capacity, flags);
    if (socket->receive_packet_info) {
        struct PacketInfo {
            ip6::Address address;
            uint32_t index;
        } info{frame.destination, frame.index};

        static_assert(sizeof(info) == 20);
        output.append(50, &info, sizeof(info));
    }
    if (socket->receive_hops) {
        int value = frame.hops;
        output.append(52, &value, sizeof(value));
    }
    if (socket->receive_traffic_class) {
        int value = frame.traffic_class;
        output.append(67, &value, sizeof(value));
    }
    return output.used;
}
} // namespace ax
