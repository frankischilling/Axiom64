// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/arch/x86_64/interrupts.hpp
 * @brief   Declares interrupt routing and timer interrupt interfaces.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Defines interrupt vectors and resolves ISA overrides to validated I/O APIC
 * inputs for boot-time controller setup.
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
#pragma once
#include <stdint.h>

namespace ax {
namespace Acpi {
struct InterruptTopology;
}

namespace Irq {
constexpr uint8_t pic_timer = 0x20;
constexpr uint8_t apic_timer = 0x30;
constexpr uint8_t spurious = 0xff;
constexpr uint32_t active_low = 1u << 13;
constexpr uint32_t level_triggered = 1u << 15;
constexpr unsigned max_inputs = 120; // The last low redirection register is 0xfe.

struct GsiRange {
    uint32_t first;
    unsigned inputs;
};

struct Route {
    unsigned controller;
    unsigned input;
    uint32_t mode;
};

using Handler = void (*)(void*);
using LineHandler = bool (*)(void*);

struct Message {
    uint32_t address;
    uint8_t vector;
};

struct Line {
    uint8_t index = 0;
    uint8_t slot = 0;
};

// Resolve an ISA interrupt to exactly one validated I/O APIC input.
constexpr bool isa_route(uint32_t gsi, uint16_t flags, const GsiRange* ranges, unsigned count,
                         Route& route) {
    unsigned polarity = flags & 3;
    unsigned trigger = (flags >> 2) & 3;
    if (flags >> 4 || polarity == 2 || trigger == 2)
        return false;
    unsigned owner = count;
    for (unsigned i = 0; i < count; ++i) {
        const auto& range = ranges[i];
        if (!range.inputs || range.inputs > max_inputs ||
            range.inputs - 1 > UINT32_MAX - range.first)
            return false;
        uint64_t end = uint64_t(range.first) + range.inputs;
        for (unsigned j = 0; j < i; ++j)
            if (ranges[j].first < end && range.first < uint64_t(ranges[j].first) + ranges[j].inputs)
                return false;
        if (gsi >= range.first && gsi - range.first < range.inputs) {
            owner = i;
        }
    }
    if (owner == count)
        return false;
    route = {owner, gsi - ranges[owner].first,
             (polarity == 3 ? active_low : 0) | (trigger == 3 ? level_triggered : 0)};
    return true;
}
} // namespace Irq

void interrupt_init_legacy();
void interrupt_init_apic(const Acpi::InterruptTopology&);
bool interrupt_apic_ready();
// Called with interrupts masked on the boot CPU. Retired vectors stay reserved
// until reboot so a message already posted by a stopped device cannot be reused.
bool interrupt_register_message(Irq::Handler, void* context, Irq::Message&);
void interrupt_retire_message(uint8_t vector);
bool interrupt_line_available(uint32_t gsi);
bool interrupt_register_line(uint32_t gsi, bool active_low, bool shared, Irq::LineHandler,
                             void* context, Irq::Line&);
void interrupt_retire_line(Irq::Line&);
bool interrupt_line_ready(const Irq::Line&);
bool interrupt_wait_for(const volatile bool& observed);
bool interrupt_dispatch(uint64_t vector);
} // namespace ax
