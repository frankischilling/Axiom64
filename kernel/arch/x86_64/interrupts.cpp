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
#include "drivers/platform/poll.hpp"
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
constexpr unsigned icr_low = 0x300, icr_high = 0x310, icr_msr = 0x830;
constexpr uint32_t icr_busy = 1 << 12;
constexpr uint8_t wake_vector = 0xf1;
constexpr unsigned max_controllers = 16;
constexpr unsigned first_message_vector = 0x40, past_message_vector = 0x80;

// These registers appear in LVT index order, including optional entries.
constexpr unsigned lvt_registers[] = {0x320, 0x350, 0x360, 0x370, 0x340, 0x330, 0x2f0};

struct LocalApic {
    volatile uint32_t* mmio;
    uint64_t address;
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

    uint32_t id() const {
        const uint32_t id = read(0x20);
        return x2 ? id : (id >> 24);
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
LocalApic ipi_local;
Irq::IpiHandler ipi_handler;
IoApic controllers[max_controllers];
Irq::GsiRange controller_ranges[max_controllers];
unsigned controller_count;
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

constexpr unsigned max_lines = 16, max_line_sources = 8;

struct LineSource {
    Irq::LineHandler call;
    void* context;
};

struct LineRoute {
    Irq::Route route;
    uint32_t gsi;
    uint8_t vector;
    bool shared, retired_by_error;
    unsigned unclaimed;
    LineSource sources[max_line_sources];
};

LineRoute lines[max_lines];

unsigned line_register(const LineRoute& line) {
    return 0x10 + 2 * line.route.input;
}

void mask_line(const LineRoute& line) {
    unsigned reg = line_register(line);
    auto& io = controllers[line.route.controller];
    io.write(reg, io.read(reg) | lvt_mask);
}

void dispatch_line(void* context) {
    auto& line = *static_cast<LineRoute*>(context);
    bool claimed = false;
    for (const auto& source : line.sources)
        if (source.call)
            claimed |= source.call(source.context);
    if (claimed)
        line.unclaimed = 0;
    else if (line.vector && !line.retired_by_error && ++line.unclaimed == 8) {
        // Drop delivery before local EOI allows a still-asserted level to retrigger.
        mask_line(line);
        line.retired_by_error = true;
        log("Interrupts: masked unclaimed I/O APIC line gsi=%u\n", uint64_t(line.gsi));
    }
}

bool locate_local_apic(LocalApic& result, uint64_t expected_address) {
    uint32_t a = 1, b, c, d;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    if (!(d & (1 << 9)))
        return false;
    uint64_t base = rdmsr(apic_base_msr);
    result.address = base & apic_address_mask;
    if (!(base & apic_global_enable) || !result.address ||
        (expected_address && result.address != expected_address))
        return false;
    result.x2 = base & apic_x2_mode;
    if (result.x2) {
        if (!(c & (1 << 21)))
            return false;
    } else {
        result.mmio = static_cast<volatile uint32_t*>(map_mmio(result.address, page_size));
        if (!result.mmio)
            return false;
    }
    return true;
}

unsigned local_apic_lvt_count(const LocalApic& apic) {
    const uint32_t version = apic.read(0x30);
    const unsigned lvt_count = ((version >> 16) & 255) + 1;
    if ((version & 255) < 0x10 || lvt_count < 4 ||
        lvt_count > sizeof(lvt_registers) / sizeof(*lvt_registers))
        return 0;
    return lvt_count;
}

bool local_apic(const Acpi::InterruptTopology& topology, LocalApic& result, unsigned& id,
                unsigned& lvt_count) {
    if (!topology.local_apic || !locate_local_apic(result, topology.local_apic))
        return false;
    lvt_count = local_apic_lvt_count(result);
    if (!lvt_count)
        return false;
    id = result.id();
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

template <class Predicate> bool observe_interrupt(Predicate observed) {
    constexpr unsigned period = 59659; // 50 ms on the independent PIT channel 2.
    uint8_t control = in8(0x61);
    for (unsigned attempt = 0; attempt < 3 && !observed(); ++attempt) {
        out8(0x61, control & ~3u);
        out8(0x43, 0xb0);
        out8(0x42, uint8_t(period));
        out8(0x42, uint8_t(period >> 8));
        out8(0x61, (control & ~2u) | 1u);
        asm volatile("sti" ::: "memory");
        for (unsigned spins = 0; spins < 2000000 && !observed() && !(in8(0x61) & 0x20); ++spins)
            asm volatile("pause");
        asm volatile("cli" ::: "memory");
    }
    out8(0x61, control);
    return observed();
}

const char* configure_apic_timer(const Acpi::InterruptTopology& topology) {
    LocalApic candidate{};
    unsigned destination, lvt_count;
    auto& ranges = controller_ranges;
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
    if (observe_interrupt([] { return probe_ticks >= 2; })) {
        apic_destination = destination;
        controller_count = topology.io_apic_count;
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

bool interrupt_apic_ready() {
    return timer_route == TimerRoute::Apic;
}

bool interrupt_prepare_ipi(Irq::IpiHandler handler) {
    if (!handler || ipi_handler || !locate_local_apic(ipi_local, 0) ||
        !local_apic_lvt_count(ipi_local))
        return false;
    ipi_handler = handler;
    log("SMP: IPI transport=%s\n", ipi_local.x2 ? "x2APIC" : "xAPIC");
    return true;
}

bool interrupt_enable_secondary_ipi() {
    if (!ipi_handler)
        return false;
    const uint64_t base = rdmsr(apic_base_msr);
    if (!(base & apic_global_enable) || (base & apic_address_mask) != ipi_local.address ||
        bool(base & apic_x2_mode) != ipi_local.x2)
        return false;
    const unsigned count = local_apic_lvt_count(ipi_local);
    if (!count)
        return false;
    for (unsigned i = 0; i < count; ++i) {
        const unsigned reg = lvt_registers[i];
        const uint32_t previous = ipi_local.read(reg);
        if ((previous & ioapic_delivery_mask) != ioapic_smi)
            ipi_local.write(reg, previous | lvt_mask);
    }
    // Only accept reserved high-priority vectors while the AP is parked.
    ipi_local.write(task_priority, 0xe0);
    ipi_local.write(spurious_register,
                    (ipi_local.read(spurious_register) & ~0x10ffu) | 0x100 | Irq::spurious);
    return true;
}

bool interrupt_send_ipi(uint32_t destination) {
    if (!ipi_handler)
        return false;
    if (ipi_local.x2) {
        // x2APIC WRMSR does not order earlier memory writes before delivery.
        asm volatile("mfence; lfence" ::: "memory");
        wrmsr(icr_msr, (uint64_t(destination) << 32) | wake_vector);
        return true;
    }
    if (destination >= 255 ||
        !DevicePoll::wait([] { return !(ipi_local.read(icr_low) & icr_busy); }, 20))
        return false;
    ipi_local.write(icr_high, destination << 24);
    ipi_local.write(icr_low, wake_vector);
    return true;
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

static bool line_unowned(uint32_t entry) {
    return (entry & lvt_mask) && (entry & ioapic_delivery_mask) != ioapic_smi &&
           !(entry & (1u << 14));
}

bool interrupt_line_available(uint32_t gsi) {
    Irq::Route route;
    return interrupt_apic_ready() &&
           Irq::isa_route(gsi, 0, controller_ranges, controller_count, route) &&
           line_unowned(controllers[route.controller].read(0x10 + 2 * route.input));
}

bool interrupt_register_line(uint32_t gsi, bool active_low, bool shared, Irq::LineHandler handler,
                             void* context, Irq::Line& subscription) {
    if (!interrupt_apic_ready() || !handler || subscription.index)
        return false;
    Irq::Route route;
    uint16_t flags = 12 | (active_low ? 3 : 1);
    if (!Irq::isa_route(gsi, flags, controller_ranges, controller_count, route))
        return false;
    unsigned spare = max_lines;
    for (unsigned index = 0; index < max_lines; ++index) {
        auto& line = lines[index];
        if (!line.vector) {
            if (spare == max_lines)
                spare = index;
            continue;
        }
        if (line.gsi != gsi)
            continue;
        if (!shared || !line.shared || line.route.mode != route.mode || line.retired_by_error)
            return false;
        for (unsigned slot = 0; slot < max_line_sources; ++slot)
            if (!line.sources[slot].call) {
                line.sources[slot] = {handler, context};
                subscription = {uint8_t(index + 1), uint8_t(slot)};
                return true;
            }
        return false;
    }
    if (spare == max_lines)
        return false;
    auto& io = controllers[route.controller];
    unsigned reg = 0x10 + 2 * route.input;
    uint32_t low = io.read(reg);
    if (!line_unowned(low))
        return false; // Another owner, firmware SMI, or outstanding level acknowledgement.
    auto& line = lines[spare];
    Irq::Message message;
    if (!interrupt_register_message(dispatch_line, &line, message))
        return false;
    line = {route, gsi, message.vector, shared, false, 0, {{handler, context}}};
    uint32_t previous_high = io.read(reg + 1);
    uint32_t destination = apic_destination << 24;
    uint32_t redirect = route.mode | message.vector;
    io.write(reg + 1, destination);
    io.write(reg, redirect);
    constexpr uint32_t writable_low = 0x1afff;
    if ((io.read(reg) & writable_low) != redirect ||
        (io.read(reg + 1) & 0xff000000) != destination) {
        io.write(reg, low);
        io.write(reg + 1, previous_high);
        interrupt_retire_message(line.vector);
        line = {};
        return false;
    }
    subscription = {uint8_t(spare + 1), 0};
    return true;
}

void interrupt_retire_line(Irq::Line& subscription) {
    if (!subscription.index)
        return;
    auto& line = lines[subscription.index - 1];
    line.sources[subscription.slot] = {};
    subscription = {};
    for (const auto& source : line.sources)
        if (source.call)
            return;
    mask_line(line);
    interrupt_retire_message(line.vector);
    line = {};
}

bool interrupt_wait_for(const volatile bool& observed) {
    return observe_interrupt([&observed] { return observed; });
}

bool interrupt_line_ready(const Irq::Line& subscription) {
    return subscription.index && !lines[subscription.index - 1].retired_by_error;
}

bool interrupt_dispatch(uint64_t vector) {
    // The LAPIC never puts its spurious vector in the in-service register.
    if (vector == Irq::spurious)
        return false;
    if (vector == wake_vector && ipi_handler) {
        if (ipi_local.in_service(wake_vector)) {
            ipi_local.write(end_of_interrupt, 0);
            ipi_handler(ipi_local.id());
        }
        return false;
    }
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
