// SPDX-License-Identifier: GPL-3.0-or-later
#include "firmware/generation.hpp"
#include "core/random/engine.hpp"
#include <assert.h>
#include <stdio.h>
#include <array>
#include <vector>

using ax::Firmware::Generation;

struct Firmware {
    std::array<uint8_t, 4> signature{'Q', 'E', 'M', 'U'};
    std::vector<uint8_t> directory = std::vector<uint8_t>(68);
    std::array<uint8_t, 4096> data{};
    uint16_t key = 0x20;
    unsigned unstable = 0;
    unsigned reads = 0;
    bool failed = false;

    Firmware() {
        directory[3] = 1;
        directory[6] = 0x10;
        directory[9] = key;
        constexpr char name[] = "etc/vmgenid_guid";
        memcpy(directory.data() + 12, name, sizeof(name));
        for (unsigned i = 0; i < 16; i++)
            data[40 + i] = 17 + i;
    }

    static bool read(void* opaque, uint16_t selector, size_t offset, void* output, size_t size) {
        auto& self = *static_cast<Firmware*>(opaque);
        self.reads++;
        if (self.failed)
            return false;
        const uint8_t* bytes = nullptr;
        size_t length = 0;
        if (selector == 0) {
            bytes = self.signature.data();
            length = self.signature.size();
        } else if (selector == 0x19) {
            bytes = self.directory.data();
            length = self.directory.size();
        } else if (selector == self.key) {
            bytes = self.data.data();
            length = self.data.size();
        }
        if (!bytes || offset > length || size > length - offset)
            return false;
        memcpy(output, bytes + offset, size);
        if (selector == self.key && self.unstable) {
            static_cast<uint8_t*>(output)[0] ^= uint8_t(self.unstable);
            self.unstable--;
        }
        return true;
    }
};

static bool initialize(Firmware& firmware) {
    Generation source{};
    uint8_t id[16]{};
    return source.initialize(Firmware::read, &firmware, id);
}

int main() {
    Firmware firmware;
    Generation source{};
    uint8_t id[16]{};
    assert(!source.active());
    assert(source.poll(id) == 0);
    assert(source.initialize(Firmware::read, &firmware, id));
    assert(source.active());
    assert(!memcmp(id, firmware.data.data() + 40, 16));
    memset(id, 0xcc, 16);
    assert(source.poll(id) == 0);
    assert(id[0] == 0xcc);
    firmware.data[40]++;
    assert(source.poll(id) == 1);
    assert(!memcmp(id, firmware.data.data() + 40, 16));
    assert(source.poll(id) == 0);
    puts("RANDOM_GENERATION_NATIVE_PASS case=changed-and-unchanged");

    // A restored host namespace may give the named file a different selector.
    firmware.key = 0x21;
    firmware.directory[9] = 0x21;
    firmware.data[40]++;
    assert(source.poll(id) == 1);
    firmware.unstable = 1;
    assert(source.poll(id) == 0);
    firmware.unstable = 8;
    assert(source.poll(id) == -1);
    firmware.failed = true;
    assert(source.poll(id) == -1);
    firmware.failed = false;
    assert(source.poll(id) == 0);
    puts("RANDOM_GENERATION_NATIVE_PASS case=namespace-stability-and-failure");

    for (unsigned kind = 0; kind < 10; kind++) {
        Firmware bad;
        switch (kind) {
        case 0:
            bad.signature[0] = 'X';
            break;
        case 1:
            bad.directory[0] = 0xff;
            break;
        case 2:
            bad.directory[3] = 0;
            break;
        case 3:
            bad.directory.resize(10);
            break;
        case 4:
            bad.directory[6] = 0x0f;
            break;
        case 5:
            bad.directory[9] = 0x1f;
            break;
        case 6:
            bad.directory[8] = 0x40;
            break;
        case 7:
            bad.directory[10] = 1;
            break;
        case 8:
            memset(bad.directory.data() + 12, 'x', 56);
            break;
        case 9: {
            std::array<uint8_t, 64> entry;
            memcpy(entry.data(), bad.directory.data() + 4, 64);
            bad.directory.insert(bad.directory.end(), entry.begin(), entry.end());
            bad.directory[3] = 2;
            break;
        }
        }
        assert(!initialize(bad));
        assert(bad.reads <= 8);
    }
    puts("RANDOM_GENERATION_NATIVE_PASS case=ten-malformed-and-bounded-inputs");

    ax::random::Generator unready;
    firmware.data[40]++;
    assert(source.poll(id) == 1);
    unready.mix(id, sizeof(id));
    assert(!unready.ready() && unready.entropy_count() == 0);
    unready.credit(128);
    firmware.data[40]++;
    assert(source.poll(id) == 1);
    unready.mix(id, sizeof(id));
    assert(!unready.ready() && unready.entropy_count() == 128);
    puts("RANDOM_GENERATION_NATIVE_PASS case=public-identifiers-never-initialize");

    uint8_t trusted[32];
    for (unsigned i = 0; i < sizeof(trusted); i++)
        trusted[i] = i + 33;
    ax::random::Generator original;
    ax::random::Generator control;
    ax::random::Generator clone;
    original.seed(trusted);
    control.seed(trusted);
    clone.seed(trusted);
    uint8_t before[32], repeated[32], distinct[32];
    assert(original.read(before, sizeof(before)) == 0);
    assert(control.read(repeated, sizeof(repeated)) == 0);
    assert(!memcmp(before, repeated, sizeof(before)));
    firmware.data[40]++;
    assert(source.poll(id) == 1);
    clone.mix(id, sizeof(id));
    assert(clone.reseed() == 0);
    assert(clone.read(distinct, sizeof(distinct)) == 0);
    assert(memcmp(before, distinct, sizeof(before)));
    assert(clone.ready() && clone.entropy_count() == 256);
    puts("RANDOM_GENERATION_NATIVE_PASS case=identical-state-control-and-immediate-rekey");
}
