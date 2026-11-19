// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/arch/x86_64/interrupts.cpp
 * @brief   Configures x86 controllers and dispatches hardware interrupts.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Programs the legacy PIC and PIT, then verifies I/O APIC delivery before
 * switching to APIC interrupt acknowledgement. Dispatches registered PCI
 * interrupt messages on the boot processor.
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
#include "arch/x86_64/interrupts.hpp"
#include "core/base.hpp"
#include "firmware/acpi.hpp"

namespace ax {
namespace {
constexpr uint32_t apic_base_msr = 0x1b;
constexpr uint64_t apic_global_enable = 1 << 11;
constexpr uint64_t apic_x2_mode = 1 << 10;
constexpr uint64_t apic_address_mask = ((1ull << 52) - 1) & ~4095ull;
constexpr uint32_t lvt_mask = 1 << 16;
constexpr uint32_t ioapic_smi = 2 << 8;
constexpr uint32_t ioapic_delivery_mask = 7 << 8;
constexpr uint32_t task_priority = 0x80, end_of_interrupt = 0xb0, spurious_register = 0xf0;
constexpr unsigned max_controllers = 16;
constexpr unsigned first_message_vector = 0x40, past_message_vector = 0x80;

// These registers appear in LVT index order, including optional entries.
constexpr unsigned lvt_registers[] = {0x320, 0x350, 0x360, 0x370, 0x340, 0x330, 0x2f0};

struct LocalApic {
    volatile uint32_t* mmio;
    bool x2;

    uint32_t read(unsigned reg) const {
        return x2 ? uint32_t(rdmsr(0x800 + (reg >> 4))) : mmio[reg / 4];
    }

    void write(unsigned reg, uint32_t value) const {
        if (x2)
            wrmsr(0x800 + (reg >> 4), value);
        else
            mmio[reg / 4] = value;
    }

    bool in_service(unsigned vector) const {
        return read(0x100 + (vector >> 5) * 16) & (1u << (vector & 31));
    }
};

struct IoApic {
    volatile uint32_t* mmio;
    uint32_t previous_low[Irq::max_inputs];

    uint32_t read(unsigned reg) const {
        mmio[0] = reg;
        return mmio[4];
    }

    void write(unsigned reg, uint32_t value) const {
        mmio[0] = reg;
        mmio[4] = value;
    }
};

LocalApic local;
IoApic controllers[max_controllers];
enum class TimerRoute { Pic, Probe, Apic };
TimerRoute timer_route;
volatile unsigned probe_ticks;
unsigned apic_destination;
unsigned next_message_vector = first_message_vector;

struct MessageHandler {
    Irq::Handler call;
    void* context;
};

MessageHandler messages[past_message_vector - first_message_vector];

bool local_apic(const Acpi::InterruptTopology& topology, LocalApic& result, unsigned& id,
                unsigned& lvt_count) {
    uint32_t a = 1, b, c, d;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    if (!(d & (1 << 9)))
        return false;
    uint64_t base = rdmsr(apic_base_msr);
    if (!(base & apic_global_enable) || (base & apic_address_mask) != topology.local_apic)
        return false;
    result.x2 = base & apic_x2_mode;
    if (result.x2) {
        if (!(c & (1 << 21)))
            return false;
    } else {
        result.mmio = static_cast<volatile uint32_t*>(map_mmio(topology.local_apic, page_size));
        if (!result.mmio)
            return false;
    }
    uint32_t version = result.read(0x30);
    lvt_count = ((version >> 16) & 255) + 1;
    if ((version & 255) < 0x10 || lvt_count < 4 ||
        lvt_count > sizeof(lvt_registers) / sizeof(*lvt_registers))
        return false;
    id = result.read(0x20);
    if (!result.x2)
        id >>= 24;
    if (id >= 255)
        return false; // An I/O APIC physical destination has eight bits. 0xff broadcasts.
    for (unsigned i = 0; i < topology.processor_count; ++i)
        if (topology.processors[i].apic_id == id && (topology.processors[i].flags & 1))
            return true;
    return false;
}

bool io_apics(const Acpi::InterruptTopology& topology, Irq::GsiRange* ranges) {
    if (!topology.io_apic_count || topology.io_apic_count > max_controllers)
        return false;
    for (unsigned i = 0; i < topology.io_apic_count; ++i) {
        const auto& io = topology.io_apics[i];
        auto& controller = controllers[i];
        controller.mmio = static_cast<volatile uint32_t*>(map_mmio(io.address, page_size));
        if (!controller.mmio)
            return false;
        uint32_t version = controller.read(1);
        if ((version & 255) < 0x10 || (version & 255) == 255)
            return false;
        ranges[i] = {io.first_gsi, ((version >> 16) & 255) + 1};
    }
    return true;
}

bool observe_timer() {
    constexpr unsigned period = 59659; // 50 ms on the independent PIT channel 2.
    uint8_t control = in8(0x61);
    for (unsigned attempt = 0; attempt < 3 && probe_ticks < 2; ++attempt) {
        out8(0x61, control & ~3u);
        out8(0x43, 0xb0);
        out8(0x42, uint8_t(period));
        out8(0x42, uint8_t(period >> 8));
        out8(0x61, (control & ~2u) | 1u);
        asm volatile("sti" ::: "memory");
        for (unsigned spins = 0; spins < 2000000 && probe_ticks < 2 && !(in8(0x61) & 0x20); ++spins)
            asm volatile("pause");
        asm volatile("cli" ::: "memory");
    }
    out8(0x61, control);
    return probe_ticks >= 2;
}

const char* configure_apic_timer(const Acpi::InterruptTopology& topology) {
    LocalApic candidate{};
    unsigned destination, lvt_count;
    Irq::GsiRange ranges[max_controllers];
    Irq::Route route;
    const auto& override = topology.isa[0];
    uint32_t gsi = override.present ? override.gsi : 0;
    if (!local_apic(topology, candidate, destination, lvt_count))
        return "local APIC unavailable or mismatched";
    if (!io_apics(topology, ranges) || !Irq::isa_route(gsi, override.present ? override.flags : 0,
                                                       ranges, topology.io_apic_count, route))
        return "invalid I/O APIC input ranges or PIT override";

    auto& controller = controllers[route.controller];
    unsigned low_register = 0x10 + route.input * 2;
    uint32_t previous_low = controller.read(low_register);
    if ((previous_low & ioapic_delivery_mask) == ioapic_smi)
        return "PIT input is owned by firmware SMI";
    uint32_t previous_high = controller.read(low_register + 1);
    uint32_t previous_priority = candidate.read(task_priority);
    uint32_t previous_spurious = candidate.read(spurious_register);
    uint32_t previous_lvt[sizeof(lvt_registers) / sizeof(*lvt_registers)];

    // Own the timer gate exclusively. Keep firmware SMI routes intact.
    out8(0x21, 0xff);
    out8(0xa1, 0xff);
    for (unsigned i = 0; i < topology.io_apic_count; ++i) {
        auto& io = controllers[i];
        for (unsigned input = 0; input < ranges[i].inputs; ++input) {
            unsigned reg = 0x10 + input * 2;
            uint32_t low = io.previous_low[input] = io.read(reg);
            if ((low & ioapic_delivery_mask) != ioapic_smi)
                io.write(reg, low | lvt_mask);
        }
    }
    for (unsigned i = 0; i < lvt_count; ++i) {
        unsigned reg = lvt_registers[i];
        previous_lvt[i] = candidate.read(reg);
        if ((previous_lvt[i] & ioapic_delivery_mask) != ioapic_smi)
            candidate.write(reg, previous_lvt[i] | lvt_mask);
    }
    candidate.write(task_priority, 0);
    // Clear EOI-broadcast suppression. The I/O APIC must see level-triggered EOIs.
    candidate.write(spurious_register, (previous_spurious & ~0x10ffu) | 0x100 | Irq::spurious);
    local = candidate;
    timer_route = TimerRoute::Probe;
    probe_ticks = 0;
    controller.write(low_register + 1, destination << 24);
    controller.write(low_register, route.mode | Irq::apic_timer);
    if (observe_timer()) {
        apic_destination = destination;
        timer_route = TimerRoute::Apic;
        log("Interrupts: %s I/O APIC PIT irq=0 gsi=%u input=%u cpu=%u ticks=%u\n",
            candidate.x2 ? "x2APIC" : "xAPIC", uint64_t(gsi), uint64_t(route.input),
            uint64_t(destination), uint64_t(probe_ticks));
        return nullptr;
    }

    controller.write(low_register, previous_low | lvt_mask);
    controller.write(low_register + 1, previous_high);
    for (unsigned i = 0; i < topology.io_apic_count; ++i) {
        auto& io = controllers[i];
        for (unsigned input = 0; input < ranges[i].inputs; ++input) {
            uint32_t low = io.previous_low[input];
            if ((low & ioapic_delivery_mask) != ioapic_smi)
                io.write(0x10 + input * 2, low);
        }
    }
    for (unsigned i = 0; i < lvt_count; ++i)
        if ((previous_lvt[i] & ioapic_delivery_mask) != ioapic_smi)
            candidate.write(lvt_registers[i], previous_lvt[i]);
    candidate.write(task_priority, previous_priority);
    candidate.write(spurious_register, previous_spurious);
    timer_route = TimerRoute::Pic;
    out8(0x21, 0xfe);
    return "PIT interrupts did not reach the boot processor";
}

bool pic_in_service(uint16_t command) {
    out8(command, 0x0b); // Read the 8259 in-service register.
    return in8(command) & 0x80;
}
} // namespace

void interrupt_init_legacy() {
    out8(0x20, 0x11);
    out8(0xa0, 0x11);
    out8(0x21, Irq::pic_timer);
    out8(0xa1, Irq::pic_timer + 8);
    out8(0x21, 4);
    out8(0xa1, 2);
    out8(0x21, 1);
    out8(0xa1, 1);
    out8(0x21, 0xfe);
    out8(0xa1, 0xff);
    out8(0x43, 0x36);
    out8(0x40, uint8_t(11932));
    out8(0x40, uint8_t(11932 >> 8));
}

void interrupt_init_apic(const Acpi::InterruptTopology& topology) {
    if (auto error = configure_apic_timer(topology))
        log("Interrupts: PIC/PIT fallback, %s\n", error);
}

bool interrupt_register_message(Irq::Handler handler, void* context, Irq::Message& result) {
    if (timer_route != TimerRoute::Apic || !handler || next_message_vector == past_message_vector)
        return false;
    unsigned vector = next_message_vector++;
    messages[vector - first_message_vector] = {handler, context};
    // Compatibility-format MSI, physical destination and fixed edge delivery.
    result = {0xfee00000u | (apic_destination << 12), uint8_t(vector)};
    return true;
}

void interrupt_retire_message(uint8_t vector) {
    if (vector >= first_message_vector && vector < next_message_vector)
        messages[vector - first_message_vector] = {};
}

bool interrupt_dispatch(uint64_t vector) {
    // The LAPIC never puts its spurious vector in the in-service register.
    if (vector == Irq::spurious)
        return false;
    if ((local.x2 || local.mmio) && local.in_service(unsigned(vector))) {
        if (vector >= first_message_vector && vector < next_message_vector) {
            const auto handler = messages[vector - first_message_vector];
            if (handler.call)
                handler.call(handler.context);
        }
        local.write(end_of_interrupt, 0);
        if (vector == Irq::apic_timer && timer_route == TimerRoute::Probe)
            probe_ticks = probe_ticks + 1;
        return vector == Irq::apic_timer && timer_route == TimerRoute::Apic;
    }
    if (vector >= Irq::pic_timer && vector < Irq::apic_timer) {
        if (vector == Irq::pic_timer + 7 && !pic_in_service(0x20))
            return false;
        if (vector >= Irq::pic_timer + 8 && (vector != Irq::pic_timer + 15 || pic_in_service(0xa0)))
            out8(0xa0, 0x20);
        out8(0x20, 0x20);
        return vector == Irq::pic_timer && timer_route == TimerRoute::Pic;
    }
    return false;
}
} // namespace ax
