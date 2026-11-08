// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/unix_datagram.hpp"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

namespace {
size_t allocations;
bool refuse, reenter;
ax::UnixDatagramQueue* releasing;
} // namespace

namespace ax {
void* alloc(size_t size) {
    if (refuse)
        return nullptr;
    void* result = malloc(size);
    if (result)
        allocations++;
    return result;
}

void release(void* pointer) {
    assert(pointer && allocations);
    allocations--;
    free(pointer);
    if (reenter) {
        reenter = false;
        releasing->clear();
    }
}
} // namespace ax

int main() {
    ax::UnixDatagramQueue queue;
    const uint8_t* bytes = nullptr;
    size_t length = 999;
    assert(!queue.front(bytes, length) && !queue.readable() && queue.available() == 0);
    uint8_t input[13007];
    for (size_t index = 0; index < sizeof(input); index++)
        input[index] = uint8_t(index * 71 + 5);
    assert(queue.append(input, sizeof(input)) == sizeof(input));
    assert(queue.append(nullptr, 0) == 0);
    input[0] ^= 255;
    assert(queue.front(bytes, length) && length == sizeof(input) && bytes[0] == 5);
    for (size_t index = 1; index < sizeof(input); index++)
        assert(bytes[index] == uint8_t(index * 71 + 5));
    assert(queue.available() == sizeof(input));
    refuse = true;
    assert(queue.append(input, 1) == -12);
    assert(queue.front(bytes, length) && length == sizeof(input) && bytes[0] == 5);
    refuse = false;
    queue.consume();
    assert(queue.readable() && queue.front(bytes, length) && length == 0 && queue.available() == 0);
    queue.consume();
    assert(!queue.readable() && !allocations);
    assert(queue.admission(SIZE_MAX) == -90);
    assert(queue.append(nullptr, SIZE_MAX) == -90 && !allocations);
    for (size_t index = 0; index < queue.record_limit; index++)
        assert(queue.append(nullptr, 0) == 0);
    assert(queue.append(nullptr, 0) == -11 && queue.readable());
    queue.consume();
    assert(queue.append(nullptr, 0) == 0);
    queue.clear();
    assert(!allocations && !queue.readable());
    uint8_t* full = static_cast<uint8_t*>(malloc(queue.byte_limit));
    assert(full);
    for (size_t index = 0; index < queue.byte_limit; index++)
        full[index] = uint8_t(index);
    assert(queue.append(full, queue.byte_limit - 32) == queue.byte_limit - 32);
    assert(queue.append(input, 1) == -11);
    assert(queue.front(bytes, length) && length == queue.byte_limit - 32 &&
           bytes[length - 1] == uint8_t(length - 1));
    queue.clear();
    free(full);
    for (unsigned round = 0; round < 2000; round++) {
        assert(queue.append(input, round % sizeof(input)) == int64_t(round % sizeof(input)));
        assert(queue.append(nullptr, 0) == 0);
        queue.consume();
        queue.clear();
        assert(!allocations && !queue.readable());
    }
    assert(queue.append(input, 17) == 17 && queue.append(input, 19) == 19);
    releasing = &queue;
    reenter = true;
    queue.consume();
    assert(!allocations && !queue.readable() && !reenter);
    queue.clear();
    puts("UNIX_DATAGRAM_POLICY_PASS copied_records zero_records bounded_pressure "
         "allocation_rollback reentrant_release reuse");
}
