// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipv4_multicast_memory.hpp"
#include <cassert>
#include <cstdlib>
#include <cstdint>

namespace {
unsigned remaining = UINT32_MAX;
size_t live = 0;
} // namespace

namespace multicast_test {
void allocation_limit(unsigned successful_allocations) {
    remaining = successful_allocations;
}

size_t live_allocations() {
    return live;
}
} // namespace multicast_test

namespace ax {
void* alloc(size_t size) {
    if (!remaining)
        return nullptr;
    void* result = std::malloc(size);
    if (result) {
        live++;
        if (remaining != UINT32_MAX)
            remaining--;
    }
    return result;
}

void release(void* memory) {
    if (!memory)
        return;
    assert(live);
    live--;
    std::free(memory);
}
} // namespace ax
