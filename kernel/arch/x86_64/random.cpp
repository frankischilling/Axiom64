// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/random.hpp"
#include "core/random/engine.hpp"
#include "core/base.hpp"
#include "drivers/random/virtio.hpp"
#include "core/time.hpp"
#include "firmware/generation.hpp"

namespace ax {
static random::Generator generator;
static random::SeedSource source(false, nullptr);
static uint64_t next_seed = 0;
constinit static Firmware::Generation generation{};
static bool generation_failed = false;

static bool firmware_read(void*, uint16_t selector, size_t offset, void* data, size_t size) {
    if (offset > 16388 || size > 64 || size > 16388 - offset)
        return false;
    uint64_t flags;
    asm volatile("pushfq; popq %0; cli" : "=r"(flags)::"memory");
    out16(0x510, selector);
    for (size_t i = 0; i < offset; i++)
        (void)in8(0x511);
    auto bytes = static_cast<uint8_t*>(data);
    for (size_t i = 0; i < size; i++)
        bytes[i] = in8(0x511);
    if (flags & (1ull << 9))
        asm volatile("sti" ::: "memory");
    return true;
}

static void generation_refresh() {
    uint8_t identifier[16]{};
    int result = generation.poll(identifier);
    generation_failed = result < 0;
    if (result > 0) {
        generator.mix(identifier, sizeof(identifier));
        bool ready = generator.ready();
        if (ready)
            (void)generator.reseed();
        log("RANDOM_VMGENID_CHANGED initialized=%u credited_bits=0\n", uint64_t(ready));
    }
    random::erase(identifier, sizeof(identifier));
}

static bool cpu_seed(void*, uint64_t& word) {
    uint8_t supplied;
    asm volatile("rdseed %0; setc %1" : "=r"(word), "=qm"(supplied)::"cc");
    asm volatile("pause");
    return supplied;
}

void random_refresh(uint64_t now) {
    generation_refresh();
    virtio_rng_poll(now);
    if (now < next_seed)
        return;
    bool seeded = random_sample_source(source, "rdseed", true);
    uint64_t interval = seeded ? 6000 : 10; // 60 seconds; failed reads retry after 100 ms.
    next_seed = now > UINT64_MAX - interval ? UINT64_MAX : now + interval;
}

void random_init(bool trust_cpu, bool trust_virtio) {
    uint32_t a = 0, b, c = 0, d;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    bool available = false;
    if (a >= 7) {
        a = 7;
        c = 0;
        asm volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
        available = b & (1u << 18);
    }
    source = random::SeedSource(trust_cpu && available, cpu_seed);
    uint32_t low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    uint64_t uncredited = uint64_t(high) << 32 | low;
    generator.mix(&uncredited, sizeof(uncredited));
    random::erase(&uncredited, sizeof(uncredited));
    log("RANDOM_SOURCE rdseed=%u trust_cpu=%u\n", uint64_t(available), uint64_t(trust_cpu));
    uint8_t identifier[16]{};
    if (generation.initialize(firmware_read, nullptr, identifier)) {
        generator.mix(identifier, sizeof(identifier));
        log("RANDOM_VMGENID_INIT transport=fw_cfg credited_bits=0\n");
    }
    random::erase(identifier, sizeof(identifier));
    virtio_rng_init(trust_virtio);
    random_refresh(0);
}

bool random_sample_source(random::SeedSource& entropy, const char* name, bool trusted) {
    bool was_ready = generator.ready();
    if (!entropy.feed(generator, trusted))
        return false;
    if (trusted)
        log(was_ready ? "RANDOM_RESEEDED source=%s bits=256\n"
                      : "RANDOM_READY source=%s bits=256\n",
            name);
    else
        log("RANDOM_MIXED source=%s bits=0\n", name);
    return true;
}

bool random_ready() {
    random_refresh(ticks);
    return generator.ready() && !generation_failed;
}

unsigned random_entropy_count() {
    random_refresh(ticks);
    return generator.entropy_count();
}

void random_credit(unsigned bits) {
    bool was_ready = generator.ready();
    generator.credit(bits);
    if (!was_ready && generator.ready())
        log("RANDOM_READY source=administrator bits=256\n");
}

int random_reseed() {
    return generator.reseed();
}

int random_read(void* data, size_t size, bool insecure) {
    random_refresh(ticks);
    if (generation_failed)
        return -5;
    return generator.read(data, size, insecure);
}

void random_mix(const void* data, size_t size) {
    generator.mix(data, size);
}
} // namespace ax
