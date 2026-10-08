// SPDX-License-Identifier: GPL-3.0-or-later
#include "boot/boot.hpp"
#include "core/time.hpp"
#include "firmware/acpi.hpp"

namespace ax {
uint64_t ticks;
static Clock::Counter timeline;
static volatile uint32_t* hpet_registers;
static bool use_tsc;

static uint64_t timestamp() {
    uint32_t low, high;
    asm volatile("lfence; rdtsc" : "=a"(low), "=d"(high)::"memory");
    return uint64_t(high) << 32 | low;
}

static const uint8_t* firmware_read(uint64_t address, size_t length, void*) {
    auto map = memmap_request.response;
    if (!map || !length || length > Acpi::max_table_bytes || address > UINT64_MAX - direct_map ||
        length - 1 > UINT64_MAX - direct_map - address)
        return nullptr;
    for (size_t i = 0; i < map->entry_count; i++) {
        auto entry = map->entries[i];
        if (address < entry->base || address - entry->base > entry->length ||
            length > entry->length - (address - entry->base))
            continue;
        // Base revision 3 does not directly map reserved/ACPI regions.
        if (entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE)
            return static_cast<const uint8_t*>(physical(address));
        if (entry->type == LIMINE_MEMMAP_RESERVED || entry->type == LIMINE_MEMMAP_ACPI_NVS ||
            entry->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE ||
            entry->type == LIMINE_MEMMAP_RESERVED_MAPPED)
            return static_cast<const uint8_t*>(map_mmio(address, length));
    }
    return nullptr;
}

static bool counter_read(uint64_t& value) {
    for (unsigned attempt = 0; attempt < 4; attempt++) {
        uint32_t high = hpet_registers[0xf4 / 4], low = hpet_registers[0xf0 / 4];
        if (high == hpet_registers[0xf4 / 4]) {
            value = uint64_t(high) << 32 | low;
            return true;
        }
    }
    return false;
}

static bool initialize_hpet(uint64_t rsdp) {
    Acpi::Hpet device;
    if (!Acpi::find_hpet(rsdp, firmware_read, nullptr, device))
        return false;
    hpet_registers = static_cast<volatile uint32_t*>(map_mmio(device.address, 1024));
    if (!hpet_registers)
        return false;
    uint32_t capabilities = hpet_registers[0], period = hpet_registers[1];
    unsigned timers = ((capabilities >> 8) & 31) + 1;
    if (!(capabilities & (1u << 13)) || capabilities != device.id || !period ||
        period > 100000000) {
        hpet_registers = nullptr;
        return false;
    }
    uint32_t configuration = hpet_registers[0x10 / 4];
    hpet_registers[0x10 / 4] = configuration & ~3u;
    // Comparator registers must fit the checked 1 KiB device window.
    if (timers < 3 || timers > (1024 - 0x100) / 0x20) {
        hpet_registers = nullptr;
        return false;
    }
    for (unsigned i = 0; i < timers; i++) {
        size_t index = (0x100 + i * 0x20) / 4;
        hpet_registers[index] = hpet_registers[index] & ~((1u << 2) | (1u << 14));
    }
    hpet_registers[0x10 / 4] = (configuration & ~2u) | 1u;
    uint64_t initial = 0, reading = 0;
    bool started = (hpet_registers[0x10 / 4] & 3) == 1 && counter_read(initial);
    for (unsigned spins = 0; started && spins < 10000; spins++) {
        if (counter_read(reading) && reading != initial &&
            timeline.reset(initial, period, 10000000000000ull))
            return true;
        asm volatile("pause");
    }
    hpet_registers[0x10 / 4] = hpet_registers[0x10 / 4] & ~3u;
    hpet_registers = nullptr;
    return false;
}

static bool initialize_tsc() {
    uint32_t a = 0, b, c = 0, d;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    if (a < 1)
        return false;
    a = 1;
    c = 0;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    if (!(d & (1u << 4)))
        return false;
    // Channel 2 is independent of the scheduling PIT. The shortest sample avoids
    // choosing a host-preemption overshoot as the counter frequency.
    uint8_t speaker = in8(0x61);
    uint64_t shortest = UINT64_MAX;
    for (unsigned sample = 0; sample < 5; sample++) {
        out8(0x61, speaker & ~3u);
        out8(0x43, 0xb0);
        out8(0x42, uint8_t(11932));
        out8(0x42, uint8_t(11932 >> 8));
        uint64_t started = timestamp();
        out8(0x61, (speaker & ~2u) | 1u);
        for (unsigned spins = 0; spins < 2000000; spins++) {
            if (in8(0x61) & 0x20) {
                uint64_t cycles = timestamp() - started;
                if (cycles >= 10000 && cycles <= 1000000000000ull)
                    shortest = min(shortest, cycles);
                break;
            }
            asm volatile("pause");
        }
    }
    out8(0x61, speaker);
    return shortest != UINT64_MAX && timeline.reset(timestamp(), 1, shortest);
}

void clock_init(uint64_t rsdp) {
    if (initialize_hpet(rsdp))
        log("Clock: HPET 64-bit counter, 100 Hz accounting\n");
    else if ((use_tsc = initialize_tsc()))
        log("Clock: calibrated TSC, fixed-frequency fallback, 100 Hz accounting\n");
    else
        log("Clock: PIT IRQ-only fallback, elapsed waits unavailable\n");
}

void clock_refresh(bool timer) {
    if (hpet_registers) {
        uint64_t reading;
        if (counter_read(reading))
            ticks = max(ticks, timeline.sample(reading));
    } else if (use_tsc)
        ticks = max(ticks, timeline.sample(timestamp()));
    else if (timer && ticks != UINT64_MAX)
        ticks++;
}
} // namespace ax
