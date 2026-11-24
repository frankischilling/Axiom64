// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/arch/x86_64/clock.cpp
 * @brief   Selects and maintains the x86 elapsed clock.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Uses supported counter sources to report elapsed time and keeps the PIT
 * fallback available when hardware calibration fails.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "boot/boot.hpp"
#include "core/time.hpp"
#include "firmware/acpi.hpp"

namespace ax {
uint64_t ticks;
static Clock::Counter timeline;
static uint64_t elapsed_us;
static constexpr uint64_t tick_ns = 10000000;
static volatile uint32_t* hpet_registers;
static uint32_t hpet_period;
static constexpr uint32_t pm_frequency = 3579545;
static Acpi::PmTimer pm_timer{};
static uint32_t pm_last;
static uint64_t pm_extended;
static uint64_t tsc_per_us;
static bool use_tsc;

static uint64_t timestamp() {
    uint32_t low, high;
    asm volatile("lfence; rdtsc" : "=a"(low), "=d"(high)::"memory");
    return uint64_t(high) << 32 | low;
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
            timeline.reset(initial, period, 1000000000)) {
            hpet_period = period;
            return true;
        }
        asm volatile("pause");
    }
    hpet_registers[0x10 / 4] = hpet_registers[0x10 / 4] & ~3u;
    hpet_registers = nullptr;
    return false;
}

static bool read_pm_timer(const Acpi::PmTimer& timer, uint32_t& reading) {
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        const uint32_t first = in32(timer.port) & timer.mask;
        const uint32_t middle = in32(timer.port) & timer.mask;
        const uint32_t last = in32(timer.port) & timer.mask;
        // Some chipsets can return a bad sample while the register is changing.
        // Check that the middle reading lies between the other two, modulo wrap.
        const uint32_t span = (last - first) & timer.mask;
        if (span <= timer.mask / 2 && ((middle - first) & timer.mask) <= span) {
            reading = middle;
            return true;
        }
    }
    return false;
}

static bool initialize_pm_timer(uint64_t rsdp) {
    Acpi::PmTimer device{};
    uint32_t initial;
    if (!Acpi::find_pm_timer(rsdp, firmware_read, nullptr, device) ||
        !read_pm_timer(device, initial))
        return false;
    for (unsigned spins = 0; spins < 4096; ++spins) {
        uint32_t reading;
        if (!read_pm_timer(device, reading))
            return false;
        const uint32_t delta = (reading - initial) & device.mask;
        if (delta && delta <= device.mask / 2) {
            if (!timeline.reset(0, 1000000, pm_frequency))
                return false;
            pm_timer = device;
            pm_last = reading;
            return true;
        }
        asm volatile("pause");
    }
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
    if (shortest == UINT64_MAX || !timeline.reset(timestamp(), 10000, shortest))
        return false;
    tsc_per_us = (shortest + 9999) / 10000;
    return true;
}

void clock_init(uint64_t rsdp, bool prefer_pm_timer) {
    if (prefer_pm_timer && initialize_pm_timer(rsdp))
        log("Clock: ACPI PM timer, %u-bit counter, 100 Hz accounting\n",
            pm_timer.mask == UINT32_MAX ? 32u : 24u);
    else if (initialize_hpet(rsdp))
        log("Clock: HPET 64-bit counter, 100 Hz accounting\n");
    else if ((use_tsc = initialize_tsc()))
        log("Clock: calibrated TSC, fixed-frequency fallback, 100 Hz accounting\n");
    else
        log("Clock: PIT IRQ-only fallback, elapsed waits unavailable\n");
    clock_realtime_init();
}

bool clock_shared_counter_ready() {
    return hpet_registers != nullptr || pm_timer.port != 0;
}

uint64_t clock_monotonic_resolution_ns() {
    return clock_shared_counter_ready() || use_tsc ? 1000 : tick_ns;
}

uint64_t clock_monotonic_ns() {
    const uint64_t resolution = clock_monotonic_resolution_ns();
    const uint64_t count = resolution == tick_ns ? ticks : elapsed_us;
    return min(count, UINT64_MAX / resolution) * resolution;
}

static void sample_clock(uint64_t reading) {
    elapsed_us = timeline.sample(reading);
    ticks = max(ticks, elapsed_us / 10000);
}

void clock_refresh(bool timer) {
    if (hpet_registers) {
        uint64_t reading;
        if (counter_read(reading))
            sample_clock(reading);
    } else if (pm_timer.port) {
        uint32_t reading;
        // The bootstrap CPU's 100 Hz tick samples well inside the 24-bit wrap
        // interval (about 4.69 s). Kernel entries serialize timeline updates.
        if (read_pm_timer(pm_timer, reading)) {
            pm_extended += (reading - pm_last) & pm_timer.mask;
            pm_last = reading;
            sample_clock(pm_extended);
        }
    } else if (use_tsc)
        sample_clock(timestamp());
    else if (timer && ticks != UINT64_MAX)
        ticks++;
}

static bool delay_pm_timer(unsigned microseconds) {
    const auto counts = (uint64_t(microseconds) * pm_frequency + 999999) / 1000000;
    uint32_t start;
    if (counts > pm_timer.mask / 2 || !read_pm_timer(pm_timer, start))
        return false;
    for (unsigned attempt = 0; attempt < 100000; ++attempt) {
        uint32_t reading;
        if (!read_pm_timer(pm_timer, reading))
            return false;
        if (((reading - start) & pm_timer.mask) >= counts)
            return true;
        asm volatile("pause");
    }
    return false;
}

bool clock_delay_us(unsigned microseconds) {
    if (pm_timer.port)
        return delay_pm_timer(microseconds);
    uint64_t start;
    uint64_t counts;
    if (hpet_registers) {
        if (!counter_read(start))
            return false;
        counts = (uint64_t(microseconds) * 1000000000 + hpet_period - 1) / hpet_period;
    } else if (use_tsc) {
        start = timestamp();
        counts = microseconds * tsc_per_us;
    } else
        return false;

    for (unsigned attempt = 0; attempt < 100000; ++attempt) {
        uint64_t reading;
        if (hpet_registers) {
            if (!counter_read(reading))
                return false;
        } else
            reading = timestamp();
        if (reading - start >= counts)
            return true;
        asm volatile("pause");
    }
    return false;
}
} // namespace ax
