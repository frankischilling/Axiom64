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

static void addresses() {
    uint8_t input[111]{1, 0, '/', 't', 'm', 'p', '/', 'x', 0, 'q'};
    ax::UnixAddressValue value;
    assert(!ax::unix_address_decode(input, 10, value));
    assert(value.length == 7 && !value.abstract());
    assert(!memcmp(value.path, "/tmp/x", 7));
    auto original = value;
    assert(ax::unix_address_decode(input, 1, value) == -22 && value.same(original));
    assert(ax::unix_address_decode(input, 111, value) == -22 && value.same(original));
    input[0] = 2;
    assert(ax::unix_address_decode(input, 10, value) == -22 && value.same(original));
    input[0] = 1;
    assert(!ax::unix_address_decode(input, 2, value) && !value.length);
    auto unbound = ax::UnixAddressName::create(value);
    assert(unbound && !unbound->address().length);
    unbound->drop();
    input[2] = 0;
    input[3] = 'a';
    input[4] = 0;
    input[5] = 'b';
    input[6] = 0;
    assert(!ax::unix_address_decode(input, 7, value));
    assert(value.abstract() && value.length == 5 && !memcmp(value.path, input + 2, 5));
    auto shorter = value;
    shorter.length--;
    assert(!value.same(shorter));
    for (size_t size = 0; size <= 111; size++) {
        uint8_t output[112];
        memset(output, 0xa5, sizeof(output));
        assert(value.output(output, size) == 7);
        assert(!memcmp(output, input, ax::min(size, size_t(7))));
        for (size_t n = ax::min(size, size_t(7)); n < sizeof(output); n++)
            assert(output[n] == 0xa5);
    }
    memset(input + 2, 'x', 108);
    assert(!ax::unix_address_decode(input, 110, value) && value.length == 109);
    assert(!value.abstract() && !value.path[108]);
    assert(value.output(nullptr, 0) == 111);
    uint8_t full[111];
    assert(value.output(full, sizeof(full)) == sizeof(full) && !full[110]);
    assert(!memcmp(input, full, 110));
    input[2] = 0;
    assert(!ax::unix_address_decode(input, 110, value) && value.length == 108 && value.abstract());
    assert(value.output(full, sizeof(full)) == 110);
    unbound = ax::UnixAddressName::create({});
    auto late_budget = ax::UnixSendBudget::create();
    ax::UnixDatagramQueue late_queue;
    assert(unbound && late_budget && late_queue.append(*late_budget, "L", 1, 0, unbound) == 1);
    assert(!late_queue.source_name());
    assert(!unbound->bind(value) && unbound->bind(value) == -22);
    assert(late_queue.source_name()->address().same(value));
    unbound->drop();
    late_budget->close();
    late_queue.clear();
    assert(!allocations);
    auto malformed = value;
    malformed.length = UINT16_MAX;
    assert(!malformed.valid() && !malformed.same(value) && !ax::UnixAddressName::create(malformed));
    memset(full, 0xa5, sizeof(full));
    assert(!malformed.output(full, sizeof(full)) && full[0] == 0xa5);
    malformed = original;
    malformed.path[1] = 0;
    assert(!malformed.valid() && !ax::UnixAddressName::create(malformed));
    refuse = true;
    assert(!ax::UnixAddressName::create(value) && !allocations);
    refuse = false;
    ax::UnixDatagramQueue queue;
    auto budget = ax::UnixSendBudget::create();
    auto name = ax::UnixAddressName::create(value);
    assert(budget && name && allocations == 2);
    refuse = true;
    assert(queue.append(*budget, "X", 1, 0, name) == -12);
    assert(!queue.source_name() && allocations == 2);
    refuse = false;
    assert(queue.append(*budget, "X", 1, 0, name) == 1);
    assert(queue.append(*budget, nullptr, 0, 0, name) == 0);
    name->drop();
    budget->close();
    assert(allocations == 4 && queue.source_name()->address().same(value));
    // A different binding can reuse the sender slot without changing old names.
    auto other = value;
    other.path[1] ^= 1;
    auto replacement = ax::UnixAddressName::create(other);
    assert(replacement && !queue.source_name()->address().same(replacement->address()));
    replacement->drop();
    queue.consume();
    assert(allocations == 3 && queue.source_name()->address().same(value));
    releasing = &queue;
    reenter = true;
    queue.consume();
    assert(!allocations && !queue.source_name() && !reenter);
    for (unsigned round = 0; round < 2000; round++) {
        budget = ax::UnixSendBudget::create();
        name = ax::UnixAddressName::create(value);
        assert(budget && name && queue.append(*budget, "Y", 1, 0, name) == 1);
        name->drop();
        budget->close();
        queue.clear();
        assert(!allocations);
    }
    budget = ax::UnixSendBudget::create();
    budget->resize(0);
    int error = 123;
    refuse = true;
    assert(!ax::UnixDatagramRecord::create(*budget, 1, error) && error == -12);
    refuse = false;
    assert(!ax::UnixDatagramRecord::create(*budget, SIZE_MAX, error) && error == -90);
    auto prepared = ax::UnixDatagramRecord::create(*budget, 4576, error);
    assert(prepared && !error && !queue.count() && !queue.readable() && !budget->writable());
    assert(budget->admission(1) == -11);
    for (size_t n = 0; n < prepared->size(); n++)
        prepared->data()[n] = uint8_t(n);
    queue.accept(prepared);
    assert(queue.count() == 1 && queue.available() == 4576);
    const uint8_t* payload;
    size_t length;
    assert(queue.front(payload, length) && length == 4576);
    for (size_t n = 0; n < length; n++)
        assert(payload[n] == uint8_t(n));
    queue.consume();
    assert(!queue.count() && budget->writable() && !budget->admission(1));
    prepared = ax::UnixDatagramRecord::create(*budget, 4576, error);
    assert(prepared && !error && !budget->writable());
    budget->close();
    assert(allocations == 2);
    prepared->drop();
    assert(!allocations && !queue.count());
}

int main() {
    addresses();
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
        "reentrant_release reuse resize sender_close source_names address_codec");
}
