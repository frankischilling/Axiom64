// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/random/sample.hpp"
#include "core/random/engine.hpp"
#include <assert.h>
#include <new>
#include <stdio.h>

using ax::EntropyRequest;

int main() {
    alignas(EntropyRequest) uint8_t storage[sizeof(EntropyRequest)]{};
    auto& request = *new (storage) EntropyRequest;
    uint8_t data[32];
    for (unsigned i = 0; i < sizeof(data); i++)
        data[i] = i + 1;
    uint64_t word = 0xa5;
    assert(!EntropyRequest::word(&request, word) && word == 0xa5);
    assert(!request.begin(0, 2, 100));
    assert(request.begin(1, 2, 100));
    assert(!request.begin(2, 3, 100));
    assert(request.complete(1, 3, data, 1) == -5); // Wrong descriptor cannot consume bytes.
    assert(request.complete(2, 2, data, 1) == -5); // Stale logical owner.
    assert(request.complete(1, 2, data, 0) == -5);
    assert(request.complete(1, 2, data, 33) == -5);
    assert(request.accumulated() == 0 && request.pending());
    assert(!request.expired(299) && request.expired(300));
    assert(request.complete(1, 2, data, 7) == 0 && request.accumulated() == 7);
    assert(request.complete(1, 2, data, 7) == -5); // Duplicate without an outstanding request.
    assert(request.begin(2, 5, 150));
    assert(request.complete(2, 5, data + 7, 25) == 1);
    ax::random::Generator generator;
    ax::random::SeedSource source(true, EntropyRequest::word, &request);
    assert(source.feed(generator, false) && !generator.ready() && generator.entropy_count() == 0);
    request.reset();
    for (auto byte : storage)
        assert(byte == 0); // Completed source bytes and ownership state are erased.

    for (unsigned i = 0; i < 32; i++) {
        assert(request.begin(i + 3, 1, 200 + i));
        assert(request.complete(i + 3, 1, data + i, 1) == (i == 31 ? 1 : 0));
    }
    assert(!source.seed(generator) && !generator.ready()); // The previous sample is repeated.
    request.reset();
    for (auto& byte : data)
        byte += 32;
    assert(request.begin(100, 3, 400));
    assert(request.complete(100, 3, data, 32) == 1);
    assert(source.seed(generator) && generator.ready());
    request.reset();
    assert(request.begin(101, 1, 600));
    assert(request.complete(101, 1, data, 1) == 0);
    assert(!request.begin(102, 1, 800)); // Partial replies cannot extend the original deadline.
    request.reset();
    assert(request.begin(103, 2, UINT64_MAX - 100));
    assert(!request.expired(UINT64_MAX - 1) && request.expired(UINT64_MAX));
    request.reset();
    for (auto byte : storage)
        assert(byte == 0);
    puts("RANDOM_VIRTIO_SAMPLE_PASS short=7+25,32x1 ownership=checked deadline=bounded "
         "erase=checked trust=explicit");
}
