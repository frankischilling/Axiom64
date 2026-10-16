// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/ext2/journal.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace ax {
void* alloc(size_t size) {
    return std::malloc(size);
}

void release(void* pointer) {
    std::free(pointer);
}
} // namespace ax

using namespace ax;

namespace {
constexpr uint32_t magic = 0xc03b3998;
constexpr uint8_t uuid[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

void put(uint8_t* p, uint32_t value) {
    p[0] = value >> 24;
    p[1] = value >> 16;
    p[2] = value >> 8;
    p[3] = value;
}

struct Device {
    unsigned size;
    bool writeback, after;
    unsigned calls = 0, fail = 0, writes = 0, flushes = 0;
    std::vector<uint8_t> durable, cache;
    std::vector<uint32_t> map;

    Device(unsigned block_size, bool volatile_cache)
        : size(block_size), writeback(volatile_cache), after(false),
          durable(size_t(block_size) * 4096), map(1024) {
        for (unsigned index = 0; index < map.size(); index++)
            map[index] = 2048 + index;
        auto header = durable.data() + size_t(map[0]) * size;
        put(header, magic);
        put(header + 4, 4);
        put(header + 12, size);
        put(header + 16, map.size());
        put(header + 20, 1);
        put(header + 24, 1);
        put(header + 40, 1);
        memcpy(header + 48, uuid, sizeof(uuid));
        put(header + 64, 1);
        for (unsigned block : {4u, 5u, 6u})
            memset(durable.data() + size_t(block) * size, block, size);
        cache = durable;
    }

    static int read(void* context, uint32_t block, void* data) {
        auto& device = *static_cast<Device*>(context);
        assert(block < 4096);
        memcpy(data, device.cache.data() + size_t(block) * device.size, device.size);
        return 0;
    }

    static int write(void* context, uint32_t block, const void* data) {
        auto& device = *static_cast<Device*>(context);
        assert(block < 4096);
        bool selected = ++device.calls == device.fail;
        if (selected && !device.after)
            return -5;
        memcpy(device.cache.data() + size_t(block) * device.size, data, device.size);
        if (!device.writeback)
            memcpy(device.durable.data() + size_t(block) * device.size, data, device.size);
        device.writes++;
        return selected ? -5 : 0;
    }

    static int flush(void* context) {
        auto& device = *static_cast<Device*>(context);
        bool selected = ++device.calls == device.fail;
        if (selected && !device.after)
            return -5;
        device.durable = device.cache;
        device.flushes++;
        return selected ? -5 : 0;
    }

    JournalStorage io() {
        return {this, size, 4096, map.data(), uint32_t(map.size()), read, write, flush};
    }

    Journal* open() {
        int error;
        auto journal = journal_open(io(), uuid, error);
        assert(journal && !error);
        return journal;
    }

    static int stage(void* context, uint32_t block, const void* data) {
        auto& device = *static_cast<Device*>(context);
        memcpy(device.cache.data() + size_t(block) * device.size, data, device.size);
        return 0;
    }
};

void outcome(Device& disk, const std::vector<std::vector<uint8_t>>& data, bool old_allowed) {
    bool old = true, updated = true;
    for (unsigned index = 0; index < data.size(); index++) {
        auto bytes = disk.cache.data() + size_t(index + 4) * disk.size;
        updated &= !memcmp(bytes, data[index].data(), disk.size);
        for (unsigned offset = 0; offset < disk.size; offset++)
            old &= bytes[offset] == index + 4;
    }
    assert(updated || (old_allowed && old));
}

unsigned fault_matrix(unsigned size, bool writeback) {
    Device baseline(size, writeback);
    std::vector<std::vector<uint8_t>> data(3, std::vector<uint8_t>(size));
    for (unsigned index = 0; index < data.size(); index++)
        memset(data[index].data(), 20 + index, size);
    // A bitmap may start with the journal magic and must survive escape/replay.
    put(data[1].data(), magic);
    JournalWrite writes[] = {{4, data[0].data()}, {5, data[1].data()}, {6, data[2].data()}};
    auto journal = baseline.open();
    assert(!journal_commit(journal, writes, 3));
    journal_close(journal);
    outcome(baseline, data, false);
    unsigned operations = baseline.calls, cases = 0;
    assert(operations == 15);
    for (bool after : {false, true})
        for (unsigned cut = 1; cut <= operations; cut++) {
            Device crashed(size, writeback);
            crashed.fail = cut;
            crashed.after = after;
            journal = crashed.open();
            assert(journal_commit(journal, writes, 3) == -5);
            journal_close(journal);
            crashed.cache = crashed.durable;
            crashed.fail = 0;
            journal = crashed.open();
            unsigned before = crashed.writes;
            assert(!journal_stage(journal, Device::stage, &crashed));
            assert(before == crashed.writes);
            outcome(crashed, data, true);
            assert(!journal_checkpoint(journal));
            journal_close(journal);
            assert(crashed.cache == crashed.durable);
            journal = crashed.open();
            assert(!journal_stage(journal, Device::stage, &crashed));
            outcome(crashed, data, true);
            journal_close(journal);
            cases++;

            Device retried(size, writeback);
            retried.fail = cut;
            retried.after = after;
            journal = retried.open();
            assert(journal_commit(journal, writes, 3) == -5);
            assert(journal_commit(journal, nullptr, 0) == -16);
            JournalWrite different[] = {
                {4, data[2].data()}, {5, data[1].data()}, {6, data[0].data()}};
            assert(journal_commit(journal, different, 3) == -16);
            retried.fail = 0;
            assert(!journal_commit(journal, writes, 3));
            outcome(retried, data, false);
            assert(retried.cache == retried.durable);
            journal_close(journal);
            cases++;
        }
    return cases;
}

void multiple_descriptors(unsigned size) {
    Device disk(size, false);
    unsigned count = (size - 28) / 8 + 2;
    std::vector<std::vector<uint8_t>> data(count, std::vector<uint8_t>(size));
    std::vector<JournalWrite> writes(count);
    for (unsigned index = 0; index < count; index++) {
        memset(data[index].data(), index & 255, size);
        writes[index] = {index + 4, data[index].data()};
    }
    auto journal = disk.open();
    assert(!journal_commit(journal, writes.data(), writes.size()));
    journal_close(journal);
    // Reopen a durable committed log before any home block was written.
    Device crash(size, false);
    crash.fail = 2 + 2 + count + 1 + 1 + 1;
    journal = crash.open();
    assert(journal_commit(journal, writes.data(), writes.size()) == -5);
    journal_close(journal);
    crash.fail = 0;
    crash.cache = crash.durable;
    journal = crash.open();
    assert(!journal_stage(journal, Device::stage, &crash));
    for (unsigned index = 0; index < count; index++)
        assert(!memcmp(crash.cache.data() + size_t(index + 4) * size, data[index].data(), size));
    assert(!journal_checkpoint(journal));
    journal_close(journal);
}

unsigned negatives() {
    unsigned cases = 0;

    struct Negative {
        unsigned offset, value, expected;
    };

    for (auto [offset, value, expected] : {Negative{0, 1, 117},
                                           {4, 3, 95},
                                           {12, 2048, 117},
                                           {16, 1023, 117},
                                           {20, 0, 117},
                                           {28, 1024, 117},
                                           {32, 5, 117},
                                           {36, 1, 95},
                                           {40, 2, 95},
                                           {44, 1, 95},
                                           {64, 2, 117},
                                           {68, 1, 117},
                                           {84, 1, 95}}) {
        Device disk(1024, false);
        put(disk.cache.data() + size_t(disk.map[0]) * disk.size + offset, value);
        int error;
        auto journal = journal_open(disk.io(), uuid, error);
        assert(!journal && error == -int(expected));
        assert(disk.writes == disk.flushes);
        cases++;
    }
    Device disk(1024, false);
    auto journal = disk.open();
    uint8_t data[1024]{};
    JournalWrite invalid[] = {{disk.map[1], data}, {4096, data}, {4, nullptr}};
    for (const auto& write : invalid) {
        assert(journal_commit(journal, &write, 1) == -117);
        cases++;
    }
    JournalWrite duplicate[] = {{4, data}, {4, data}};
    assert(journal_commit(journal, duplicate, 2) == -22);
    cases++;
    assert(!disk.writes && !disk.flushes);
    journal_close(journal);
    return cases;
}

unsigned replay_controls() {
    auto header = [](Device& disk, unsigned position, unsigned type, unsigned sequence) {
        auto bytes = disk.cache.data() + size_t(disk.map[position]) * disk.size;
        memset(bytes, 0, disk.size);
        put(bytes, magic);
        put(bytes + 4, type);
        put(bytes + 8, sequence);
        return bytes;
    };
    auto transaction = [&](Device& disk, unsigned position, unsigned sequence, unsigned value) {
        auto descriptor = header(disk, position, 1, sequence);
        put(descriptor + 12, 4);
        put(descriptor + 16, 8);
        memcpy(descriptor + 20, uuid, 16);
        memset(disk.cache.data() + size_t(disk.map[position + 1]) * disk.size, value, disk.size);
        header(disk, position + 2, 2, sequence);
    };
    unsigned cases = 0;
    for (unsigned mode = 0; mode < 3; mode++) {
        Device disk(1024, false);
        put(disk.cache.data() + size_t(disk.map[0]) * disk.size + 28, 1);
        transaction(disk, 1, 1, 20);
        auto revoke = header(disk, 4, 5, 2);
        put(revoke + 12, 20);
        put(revoke + 16, 4);
        if (mode) {
            header(disk, 5, 2, 2);
            if (mode == 2)
                transaction(disk, 6, 3, 30);
        }
        disk.durable = disk.cache;
        auto journal = disk.open();
        assert(!journal_stage(journal, Device::stage, &disk));
        uint8_t expected = mode == 0 ? 20 : mode == 1 ? 4 : 30;
        for (unsigned offset = 0; offset < disk.size; offset++)
            assert(disk.cache[size_t(4) * disk.size + offset] == expected);
        assert(!journal_checkpoint(journal));
        journal_close(journal);
        cases++;
    }
    Device wrapped(1024, false);
    put(wrapped.cache.data() + size_t(wrapped.map[0]) * wrapped.size + 28, 1021);
    transaction(wrapped, 1021, 1, 40);
    wrapped.durable = wrapped.cache;
    auto journal = wrapped.open();
    assert(!journal_stage(journal, Device::stage, &wrapped));
    for (unsigned offset = 0; offset < wrapped.size; offset++)
        assert(wrapped.cache[size_t(4) * wrapped.size + offset] == 40);
    assert(!journal_checkpoint(journal));
    journal_close(journal);
    cases++;
    for (unsigned mode = 0; mode < 4; mode++) {
        Device disk(1024, false);
        put(disk.cache.data() + size_t(disk.map[0]) * disk.size + 28, 1);
        transaction(disk, 1, 1, 20);
        auto descriptor = disk.cache.data() + size_t(disk.map[1]) * disk.size;
        if (mode < 2)
            put(descriptor + 12, mode ? disk.map[3] : 4096);
        else if (mode == 2)
            descriptor[20] ^= 1;
        else
            put(descriptor + 16, 16);
        journal = disk.open();
        assert(journal_stage(journal, Device::stage, &disk) == (mode == 3 ? -95 : -117));
        assert(!disk.writes && !disk.flushes);
        assert(journal_checkpoint(journal) == -22);
        journal_close(journal);
        cases++;
    }
    Device disk(1024, false);
    put(disk.cache.data() + size_t(disk.map[0]) * disk.size + 28, 1);
    transaction(disk, 1, 1, 20);
    journal = disk.open();
    auto refused = [](void*, uint32_t, const void*) { return -5; };
    assert(journal_stage(journal, refused, &disk) == -5);
    assert(journal_checkpoint(journal) == -22 && !disk.writes && !disk.flushes);
    assert(!journal_stage(journal, Device::stage, &disk));
    assert(!journal_checkpoint(journal));
    journal_close(journal);
    return cases + 1;
}

unsigned restart_sequences(unsigned size, bool writeback) {
    unsigned cases = 0;
    for (uint32_t sequence : {42u, UINT32_MAX})
        for (bool incomplete : {false, true}) {
            Device seed(size, writeback);
            auto header = seed.cache.data() + size_t(seed.map[0]) * size;
            put(header + 24, sequence);
            put(header + 28, incomplete ? 1 : 0);
            auto descriptor = seed.cache.data() + size_t(seed.map[1]) * size;
            put(descriptor, magic);
            put(descriptor + 4, 1);
            put(descriptor + 8, sequence);
            put(descriptor + 12, 4);
            put(descriptor + 16, 8);
            memcpy(descriptor + 20, uuid, sizeof(uuid));
            memset(seed.cache.data() + size_t(seed.map[2]) * size, 20, size);
            if (!incomplete) {
                auto commit = seed.cache.data() + size_t(seed.map[3]) * size;
                put(commit, magic);
                put(commit + 4, 2);
                put(commit + 8, sequence);
            }
            seed.durable = seed.cache;
            auto journal = seed.open();
            assert(!journal_stage(journal, Device::stage, &seed));
            assert(!journal_checkpoint(journal));
            journal_close(journal);
            if (incomplete) {
                // An abandoned transaction must not retain its ID after recovery.
                header = seed.cache.data() + size_t(seed.map[0]) * size;
                assert(memcmp(header + 24, descriptor + 8, 4));
            }
            std::vector<std::vector<uint8_t>> data(1, std::vector<uint8_t>(size, 30));
            JournalWrite update{4, data[0].data()};
            Device baseline = seed;
            baseline.calls = 0;
            journal = baseline.open();
            assert(!journal_commit(journal, &update, 1));
            journal_close(journal);
            unsigned operations = baseline.calls;
            for (bool after : {false, true})
                for (unsigned cut = 1; cut <= operations; cut++) {
                    Device crashed = seed;
                    crashed.calls = 0;
                    crashed.fail = cut;
                    crashed.after = after;
                    journal = crashed.open();
                    assert(journal_commit(journal, &update, 1) == -5);
                    journal_close(journal);
                    crashed.cache = crashed.durable;
                    crashed.fail = 0;
                    journal = crashed.open();
                    assert(!journal_stage(journal, Device::stage, &crashed));
                    // Neither an old descriptor nor a stale commit may publish 20.
                    outcome(crashed, data, true);
                    assert(!journal_checkpoint(journal));
                    journal_close(journal);
                    crashed.cache = crashed.durable;
                    journal = crashed.open();
                    assert(!journal_stage(journal, Device::stage, &crashed));
                    outcome(crashed, data, true);
                    journal_close(journal);
                    cases++;
                }
        }
    return cases;
}
} // namespace

int main() {
    unsigned cases = 0, restarts = 0;
    for (unsigned size : {1024u, 2048u, 4096u}) {
        for (bool writeback : {false, true}) {
            cases += fault_matrix(size, writeback);
            restarts += restart_sequences(size, writeback);
        }
        multiple_descriptors(size);
    }
    printf("EXT2_JOURNAL_NATIVE_PASS crash_and_retry_cases=%u negatives=%u replay_controls=%u "
           "restart_cases=%u layouts=3\n",
           cases, negatives(), replay_controls(), restarts);
}
