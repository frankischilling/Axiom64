// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/socket_options.hpp"
#include "net/ipv4.hpp"
#include "net/ipv6.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
bool option_write(Task& task, uint64_t destination, const void* bytes, size_t length) {
    auto source = static_cast<const uint8_t*>(bytes);
    while (length) {
        size_t copied = min(length, size_t(page_size - destination % page_size));
        if (!task.memory->space.copy_out(destination, source, copied))
            return false;
        destination += copied;
        source += copied;
        length -= copied;
    }
    return true;
}
} // namespace

int socket_integer_result(Task& task, int value, uint32_t capacity, uint64_t value_pointer,
                          uint64_t length_pointer) {
    uint32_t copied = min(capacity, uint32_t(sizeof(value)));
    if (!option_write(task, length_pointer, &copied, sizeof(copied)) ||
        !option_write(task, value_pointer, &value, copied))
        return -14;
    return 0;
}

int socket_device_option(Task& task, unsigned index, uint64_t value, uint64_t length_pointer) {
    uint32_t capacity;
    if (!task.memory->space.copy_in(&capacity, length_pointer, sizeof(capacity)))
        return -14;
    if (int32_t(capacity) < 0 || (index && capacity < 16))
        return -22;
    static_assert(ipv4_loopback == ipv6_loopback);
    const char* name = "";
    if (index == ipv4_loopback)
        name = "lo";
    else if (index) {
        auto info = net_info(index);
        if (!info)
            return -19;
        name = info->name;
    }
    uint32_t actual = name[0] ? uint32_t(strlen(name) + 1) : 0;
    if (!option_write(task, value, name, actual) ||
        !option_write(task, length_pointer, &actual, sizeof(actual)))
        return -14;
    return 0;
}
} // namespace ax
