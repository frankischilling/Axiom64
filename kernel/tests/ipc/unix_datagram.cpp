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
[[noreturn]] void panic(const char*) {
    abort();
}

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
    auto budget = ax::UnixSendBudget::create();
    assert(budget && allocations == 1 && budget->size() == 212992 && budget->writable());
    const uint8_t* bytes = nullptr;
    size_t length = 999;
    assert(!queue.front(bytes, length) && !queue.readable() && queue.available() == 0);
    uint8_t input[13007];
    for (size_t index = 0; index < sizeof(input); index++)
        input[index] = uint8_t(index * 71 + 5);
    assert(queue.append(*budget, input, sizeof(input)) == sizeof(input));
    assert(queue.append(*budget, nullptr, 0) == 0);
    input[0] ^= 255;
    assert(queue.front(bytes, length) && length == sizeof(input) && bytes[0] == 5);
    for (size_t index = 1; index < sizeof(input); index++)
        assert(bytes[index] == uint8_t(index * 71 + 5));
    assert(queue.available() == sizeof(input));
    refuse = true;
    assert(queue.append(*budget, input, 1) == -12);
    assert(queue.front(bytes, length) && length == sizeof(input) && bytes[0] == 5);
    refuse = false;
    queue.consume();
    assert(queue.readable() && queue.front(bytes, length) && length == 0 && queue.available() == 0);
    queue.consume();
    assert(!queue.readable() && allocations == 1);
    assert(budget->admission(SIZE_MAX) == -90);
    assert(queue.append(*budget, nullptr, SIZE_MAX) == -90 && allocations == 1);
    unsigned empty_records = 0;
    while (!budget->admission(0)) {
        assert(queue.append(*budget, nullptr, 0) == 0);
        assert(++empty_records <= 10000);
    }
    assert(empty_records > 128 && queue.append(*budget, nullptr, 0) == -11 && queue.readable());
    assert(!budget->writable());
    queue.consume();
    assert(queue.append(*budget, nullptr, 0) == 0);
    queue.clear();
    assert(allocations == 1 && !queue.readable() && budget->writable());
    size_t limit = budget->size();
    uint8_t* full = static_cast<uint8_t*>(malloc(limit));
    assert(full);
    for (size_t index = 0; index < limit; index++)
        full[index] = uint8_t(index);
    assert(queue.append(*budget, full, limit - 32) == int64_t(limit - 32));
    assert(queue.append(*budget, input, 1) == -11);
    assert(queue.front(bytes, length) && length == limit - 32 &&
           bytes[length - 1] == uint8_t(length - 1));
    queue.clear();
    free(full);
    for (unsigned round = 0; round < 2000; round++) {
        assert(queue.append(*budget, input, round % sizeof(input)) ==
               int64_t(round % sizeof(input)));
        assert(queue.append(*budget, nullptr, 0) == 0);
        queue.consume();
        queue.clear();
        assert(allocations == 1 && !queue.readable() && budget->writable());
    }
    assert(queue.append(*budget, input, 17) == 17 && queue.append(*budget, input, 19) == 19);
    releasing = &queue;
    reenter = true;
    queue.consume();
    assert(allocations == 1 && !queue.readable() && !reenter);
    queue.clear();
    assert(ax::unix_buffer_size(0, true) == 4608 && ax::unix_buffer_size(0, false) == 2304);
    assert(ax::unix_buffer_size(UINT32_MAX, true) == 425984);
    assert(queue.append(*budget, input, 7001) == 7001);
    budget->resize(0);
    assert(budget->size() == 4608 && budget->admission(4577) == -90 && budget->admission(1) == -11);
    budget->resize(65536);
    assert(budget->size() == 131072 && budget->admission(1) == 0);
    queue.clear();
    budget->close();
    assert(!allocations);
    budget = ax::UnixSendBudget::create();
    budget->resize(32768);
    auto entry_limit = budget->size();
    while (!budget->admission(7001))
        assert(queue.append(*budget, input, 7001) == 7001);
    assert(budget->admission(10000, entry_limit) == -11);
    budget->resize(0);
    assert(budget->admission(10000, entry_limit) == -11);
    queue.clear();
    assert(budget->admission(10000) == -90 && !budget->admission(10000, entry_limit));
    assert(queue.append(*budget, input, 10000, entry_limit) == 10000);
    assert(queue.front(bytes, length) && length == 10000);
    queue.clear();
    assert(queue.append(*budget, input, 10000) == -90);
    budget->close();
    assert(!allocations);
    // The sender's socket slot may close before any of its queued data.
    budget = ax::UnixSendBudget::create();
    auto second = ax::UnixSendBudget::create();
    assert(budget && second);
    assert(queue.append(*budget, input, 77) == 77);
    assert(queue.append(*second, input, 79) == 79);
    budget->close();
    assert(allocations == 4);
    queue.consume();
    assert(allocations == 2 && second->writable());
    second->close();
    queue.clear();
    assert(!allocations);
    refuse = true;
    assert(!ax::UnixSendBudget::create() && !allocations);
    refuse = false;
    puts(
        "UNIX_DATAGRAM_POLICY_PASS copied_records zero_records sender_pressure allocation_rollback "
        "reentrant_release reuse resize sender_close");
}
