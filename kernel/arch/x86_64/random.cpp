// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/random.hpp"
#include "core/random/engine.hpp"
#include "core/base.hpp"

namespace ax {
static random::Generator generator;
static random::SeedSource source(false, nullptr);
static uint64_t next_seed = 0;

static bool cpu_seed(void*, uint64_t& word) {
    uint8_t supplied;
    asm volatile("rdseed %0; setc %1" : "=r"(word), "=qm"(supplied)::"cc");
    asm volatile("pause");
    return supplied;
}

void random_refresh(uint64_t now) {
    if (now < next_seed)
        return;
    bool was_ready = generator.ready();
    bool seeded = source.seed(generator);
    uint64_t interval = seeded ? 6000 : 10; // 60 seconds; failed reads retry after 100 ms.
    next_seed = now > UINT64_MAX - interval ? UINT64_MAX : now + interval;
    if (seeded)
        log(was_ready ? "RANDOM_RESEEDED source=rdseed bits=256\n"
                      : "RANDOM_READY source=rdseed bits=256\n");
}

void random_init(bool trust_cpu) {
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
    random_refresh(0);
}

bool random_ready() {
    return generator.ready();
}

int random_read(void* data, size_t size, bool insecure) {
    return generator.read(data, size, insecure);
}

void random_mix(const void* data, size_t size) {
    generator.mix(data, size);
}
} // namespace ax
