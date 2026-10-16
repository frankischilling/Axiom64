// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/eventfd.hpp"
#include "fs/vfs.hpp"

namespace ax {
struct Eventfd {
    uint64_t count;
    bool semaphore;
};

Handle* open_eventfd(uint32_t initial, bool semaphore, bool nonblocking, int& error) {
    error = -12;
    auto counter = static_cast<Eventfd*>(alloc(sizeof(Eventfd)));
    if (!counter)
        return nullptr;
    *counter = {initial, semaphore};
    auto handle = open_handle(nullptr, 2 | (nonblocking ? 04000 : 0), &error);
    if (!handle) {
        release(counter);
        return nullptr;
    }
    handle->event = counter;
    return handle;
}

void close_eventfd(Eventfd* counter) {
    release(counter);
}

bool eventfd_ready(const Eventfd* counter, bool write) {
    return write ? counter->count < UINT64_MAX - 1 : counter->count != 0;
}

int64_t eventfd_read(Eventfd* counter, void* output, size_t length) {
    if (length < sizeof(uint64_t))
        return -22;
    if (!counter->count)
        return -11;
    uint64_t value = counter->semaphore ? 1 : counter->count;
    counter->count -= value;
    memcpy(output, &value, sizeof(value));
    return sizeof(value);
}

int64_t eventfd_write(Eventfd* counter, const void* input, size_t length) {
    if (length != sizeof(uint64_t))
        return -22;
    uint64_t value;
    memcpy(&value, input, sizeof(value));
    if (value == UINT64_MAX)
        return -22;
    if (value > UINT64_MAX - 1 - counter->count)
        return -11;
    counter->count += value;
    return sizeof(value);
}
} // namespace ax
