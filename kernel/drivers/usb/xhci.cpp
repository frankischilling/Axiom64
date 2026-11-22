// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/usb/xhci.cpp
 * @brief   xHCI controller and root device probe.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Claims a PCI controller, validates its DMA rings, and reads the descriptors
 * of devices attached to root ports before halting the controller.
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
#include "drivers/usb/xhci.hpp"
#include "drivers/platform/pci.hpp"
#include "drivers/platform/poll.hpp"
#include "mm/dma.hpp"

namespace ax {
namespace {
using Registers = volatile uint32_t*;

constexpr uint32_t run = 1, reset = 2, interrupt_enable = 4, host_error_enable = 8;
constexpr uint32_t halted = 1, host_error = (1 << 2) | (1 << 12), not_ready = 1 << 11;
constexpr uint16_t pci_memory = 2, pci_master = 4, pci_intx_disable = 0x400;
constexpr unsigned command_reg = 0x00, status_reg = 0x04, page_size_reg = 0x08;
constexpr unsigned crcr = 0x18, dcbaap = 0x30, configure = 0x38;
constexpr unsigned iman = 0, imod = 4, erstsz = 8, erstba = 0x10, erdp = 0x18;
constexpr unsigned interrupter_zero = 0x20, port_base = 0x400, port_stride = 0x10;
constexpr unsigned bios_owned = 1 << 16, os_owned = 1 << 24;
constexpr unsigned legacy_preserved = (7 << 1) | (255 << 5) | (7 << 17);
constexpr unsigned legacy_event_status = 7u << 29;
constexpr unsigned ring_size = 64, max_scratchpads = 128, max_controllers = 4;
constexpr unsigned timeout_ticks = 100, commands_to_check = 130;
constexpr unsigned descriptor_size = 18, device_pages = 4;
constexpr unsigned enable_slot = 9, address_device = 11, evaluate_context = 13, no_op = 23,
                   transfer_event = 32, command_event = 33, port_event = 34;
constexpr uint32_t port_connected = 1, port_enabled = 2, port_reset = 1 << 4;
constexpr uint32_t port_configuration = (1 << 9) | (3 << 14) | (7 << 25);

struct Trb {
    uint64_t parameter;
    uint32_t status;
    uint32_t control;
};

struct Segment {
    uint64_t base;
    uint32_t entries;
    uint32_t reserved;
};

static_assert(sizeof(Trb) == 16 && sizeof(Segment) == 16);

uint32_t read(Registers bank, unsigned offset) {
    return bank[offset / 4];
}

void write(Registers bank, unsigned offset, uint32_t value) {
    bank[offset / 4] = value;
}

void write_address(Registers bank, unsigned offset, uint64_t address) {
    write(bank, offset, address);
    write(bank, offset + 4, address >> 32);
}

bool claim_firmware(Registers base, unsigned span, uint32_t hcc) {
    unsigned offset = (hcc >> 16) * 4;
    for (unsigned hop = 0; offset && hop < 64; ++hop) {
        if (offset < 0x20 || offset > span - 4)
            return false;
        const auto header = read(base, offset);
        if ((header & 0xff) == 1) {
            if (offset > span - 8)
                return false;
            write(base, offset, header | os_owned);
            if (!DevicePoll::wait([&] { return !(read(base, offset) & bios_owned); },
                                  timeout_ticks))
                return false;
            const auto control = read(base, offset + 4);
            write(base, offset + 4, (control & legacy_preserved) | legacy_event_status);
        }
        const unsigned next = ((header >> 8) & 0xff) * 4;
        offset = next ? offset + next : 0;
    }
    return !offset;
}

bool quiet_interrupts(const PciFunction& pci) {
    if (auto offset = pci.find_capability(5)) {
        pci.write16(offset + 2, pci.read16(offset + 2) & ~1u);
        if (pci.read16(offset + 2) & 1)
            return false;
    }
    if (auto offset = pci.find_capability(0x11)) {
        pci.write16(offset + 2, (pci.read16(offset + 2) & ~0x8000u) | 0x4000);
        if (pci.read16(offset + 2) & 0x8000)
            return false;
    }
    return true;
}

struct Controller {
    Registers operational, interrupter, doorbell;
    unsigned slots, scratchpads, context_words;
    unsigned command_index = 0, event_index = 0, command_cycle = 1, event_cycle = 1;
    uint64_t dma = 0;
    uint64_t devices[256]{};

    unsigned pages() const {
        return scratchpads ? 5 + scratchpads : 4;
    }

    bool stop() const {
        write(operational, command_reg,
              read(operational, command_reg) & ~(run | interrupt_enable | host_error_enable));
        return DevicePoll::wait([&] { return read(operational, status_reg) & halted; },
                                timeout_ticks);
    }

    bool initialize() {
        if (!DevicePoll::wait([&] { return !(read(operational, status_reg) & not_ready); },
                              timeout_ticks) ||
            !stop())
            return false;
        write(operational, command_reg, reset);
        if (!DevicePoll::wait(
                [&] {
                    return !(read(operational, command_reg) & reset) &&
                           !(read(operational, status_reg) & not_ready);
                },
                timeout_ticks) ||
            !(read(operational, page_size_reg) & 1) || (read(operational, status_reg) & host_error))
            return false;

        dma = Dma::allocate(pages(), Dma::pci);
        if (!dma)
            return false;
        auto dcbaa = static_cast<uint64_t*>(physical(dma));
        if (scratchpads) {
            dcbaa[0] = dma + 4 * page_size;
            auto scratch = static_cast<uint64_t*>(physical(dcbaa[0]));
            for (unsigned i = 0; i < scratchpads; ++i)
                scratch[i] = dma + (5 + i) * page_size;
        }
        auto segment = static_cast<Segment*>(physical(dma + 3 * page_size));
        *segment = {dma + 2 * page_size, ring_size, 0};
        __atomic_thread_fence(__ATOMIC_RELEASE);
        write_address(operational, dcbaap, dma);
        write_address(operational, crcr, (dma + page_size) | 1);
        write(operational, configure, slots);
        write(interrupter, iman, 1); // Clear pending events and leave interrupt delivery disabled.
        write(interrupter, imod, 0);
        write(interrupter, erstsz, 1);
        write_address(interrupter, erdp, dma + 2 * page_size);
        write_address(interrupter, erstba, dma + 3 * page_size);
        write(operational, command_reg, run);
        return DevicePoll::wait([&] { return !(read(operational, status_reg) & halted); },
                                timeout_ticks);
    }

    bool completion(uint64_t expected, unsigned type, Trb& result) {
        bool success = false;
        auto events = static_cast<volatile Trb*>(physical(dma + 2 * page_size));
        bool complete = DevicePoll::wait(
            [&] {
                if (read(operational, status_reg) & (halted | host_error))
                    return true;
                const auto control = events[event_index].control;
                if ((control & 1) != event_cycle)
                    return false;
                __atomic_thread_fence(__ATOMIC_ACQUIRE);
                result = {events[event_index].parameter, events[event_index].status, control};
                if (++event_index == ring_size) {
                    event_index = 0;
                    event_cycle ^= 1;
                }
                write_address(interrupter, erdp,
                              (dma + 2 * page_size + event_index * sizeof(Trb)) | 8);
                const auto event_type = (control >> 10) & 63;
                if (event_type == port_event) // Port status remains available in PORTSC.
                    return false;
                success = event_type == type && result.parameter == expected &&
                          (result.status >> 24) == 1;
                return true;
            },
            timeout_ticks);
        return complete && success;
    }

    bool command(unsigned type = no_op, uint64_t parameter = 0, unsigned slot = 0,
                 unsigned* result_slot = nullptr) {
        constexpr uint32_t link = 6u << 10, toggle = 2;
        const uint64_t command_ring = dma + page_size;
        auto ring = static_cast<volatile Trb*>(physical(command_ring));
        const uint64_t submitted = command_ring + command_index * sizeof(Trb);
        auto& item = ring[command_index];
        item.parameter = parameter;
        item.status = 0;
        if (command_index + 2 == ring_size) {
            auto& tail = ring[ring_size - 1];
            tail.parameter = command_ring;
            tail.status = 0;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            tail.control = link | toggle | command_cycle;
        }
        __atomic_thread_fence(__ATOMIC_RELEASE);
        item.control = (slot << 24) | (type << 10) | command_cycle;
        if (++command_index == ring_size - 1) {
            command_index = 0;
            command_cycle ^= 1;
        }
        __atomic_thread_fence(__ATOMIC_RELEASE);
        write(doorbell, 0, 0);

        Trb event{};
        if (!completion(submitted, command_event, event))
            return false;
        const unsigned completed_slot = event.control >> 24;
        if (result_slot)
            *result_slot = completed_slot;
        return !slot || slot == completed_slot;
    }

    bool read_descriptor(unsigned slot, unsigned first, unsigned length) {
        const uint64_t transfer = devices[slot] + 2 * page_size;
        auto ring = static_cast<volatile Trb*>(physical(transfer));
        constexpr uint32_t setup = (2 << 10) | (1 << 6) | (3 << 16);
        constexpr uint32_t data_in = (3 << 10) | (1 << 16);
        constexpr uint32_t status_out = (4 << 10) | (1 << 5);
        ring[first].parameter = (uint64_t(length) << 48) | 0x01000680;
        ring[first].status = 8;
        ring[first + 1].parameter = devices[slot] + 3 * page_size;
        ring[first + 1].status = length;
        ring[first + 1].control = data_in | 1;
        ring[first + 2].parameter = 0;
        ring[first + 2].status = 0;
        ring[first + 2].control = status_out | 1;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        ring[first].control = setup | 1;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        write(doorbell, slot * 4, 1); // Endpoint zero has device-context index 1.
        Trb event{};
        return completion(transfer + (first + 2) * sizeof(Trb), transfer_event, event) &&
               (event.control >> 24) == slot && ((event.control >> 16) & 31) == 1;
    }

    bool enable_port(unsigned port, unsigned& speed) {
        unsigned offset = port_base + (port - 1) * port_stride;
        uint32_t status = read(operational, offset);
        if (!(status & port_enabled)) {
            write(operational, offset, (status & port_configuration) | port_reset);
            if (!DevicePoll::wait(
                    [&] {
                        status = read(operational, offset);
                        return !(status & (port_connected | port_reset)) ||
                               (status & (port_enabled | port_reset)) == port_enabled;
                    },
                    timeout_ticks))
                return false;
        }
        speed = (status >> 10) & 15;
        return (status & (port_enabled | port_connected)) == (port_enabled | port_connected) &&
               speed >= 1 && speed <= 5;
    }

    bool probe_device(unsigned port) {
        unsigned speed, slot = 0;
        if (!enable_port(port, speed) || !command(enable_slot, 0, 0, &slot) || !slot ||
            slot > slots || devices[slot])
            return false;
        const uint64_t input = Dma::allocate(device_pages, Dma::pci);
        if (!input)
            return false;
        devices[slot] = input;
        auto contexts = static_cast<uint32_t*>(physical(input));
        auto slot_context = contexts + context_words;
        auto endpoint = slot_context + context_words;
        const uint64_t transfer = input + 2 * page_size;
        const unsigned initial_packet = speed >= 4 ? 512 : speed == 3 ? 64 : 8;
        contexts[1] = 3; // Add the slot and default control endpoint.
        slot_context[0] = (1u << 27) | (speed << 20);
        slot_context[1] = port << 16;
        endpoint[1] = (initial_packet << 16) | (4 << 3) | (3 << 1);
        endpoint[2] = uint32_t(transfer) | 1;
        endpoint[3] = transfer >> 32;
        endpoint[4] = 8;
        static_cast<uint64_t*>(physical(dma))[slot] = input + page_size;
        if (!command(address_device, input, slot) || !read_descriptor(slot, 0, 8))
            return false;
        auto descriptor = static_cast<const uint8_t*>(physical(input + 3 * page_size));
        if (descriptor[0] != descriptor_size || descriptor[1] != 1)
            return false;
        const unsigned packet = speed >= 4 && descriptor[7] == 9 ? 512 : descriptor[7];
        if (packet != initial_packet) {
            if (speed != 1 || (packet != 16 && packet != 32 && packet != 64))
                return false;
            auto output_endpoint =
                static_cast<const uint32_t*>(physical(input + page_size)) + context_words;
            memcpy(endpoint, output_endpoint, context_words * sizeof(uint32_t));
            endpoint[0] &= ~7u;
            endpoint[1] = (endpoint[1] & 0xffff) | (packet << 16);
            contexts[1] = 2; // Change only the default endpoint's maximum packet size.
            if (!command(evaluate_context, input, slot))
                return false;
        }
        if (!read_descriptor(slot, 3, descriptor_size) || descriptor[0] != descriptor_size ||
            descriptor[1] != 1 || !descriptor[17])
            return false;
        log("xhci-device: port=%u speed=%u vendor=%x product=%x configurations=%u\n",
            uint64_t(port), uint64_t(speed), uint64_t(descriptor[8] | (descriptor[9] << 8)),
            uint64_t(descriptor[10] | (descriptor[11] << 8)), uint64_t(descriptor[17]));
        return true;
    }
};

unsigned visited;

void probe(const PciFunction& pci) {
    if (visited == max_controllers || pci.read16(0x0a) != 0x0c03 || pci.read8(9) != 0x30)
        return;
    ++visited;
    PciBar bar;
    uint64_t address;
    if (pci.probe_bar(0, PciBarSpace::memory, bar) != PciBarStatus::valid)
        return;
    const unsigned span = min(bar.size, uint64_t(64 * 1024));
    if (span < 0x1000 || !bar.range(0, span, address))
        return;
    auto base = static_cast<Registers>(map_mmio(address, span));
    if (!base)
        return;
    const uint16_t original = pci.read16(4);
    pci.write16(4, (original & ~7u) | pci_memory | pci_intx_disable);
    if ((pci.read16(4) & (pci_memory | pci_master | pci_intx_disable)) !=
        (pci_memory | pci_intx_disable)) {
        pci.write16(4, original);
        return;
    }
    const auto capabilities = read(base, 0);
    const auto hcs1 = read(base, 4);
    const auto hcs2 = read(base, 8);
    const auto hcc = read(base, 0x10);
    const unsigned length = capabilities & 0xff, version = capabilities >> 16;
    const unsigned doorbell = read(base, 0x14) & ~3u, runtime = read(base, 0x18) & ~31u;
    const unsigned slots = hcs1 & 0xff, ports = hcs1 >> 24;
    const unsigned scratchpads = (((hcs2 >> 21) & 31) << 5) | (hcs2 >> 27);
    if (version < 0x0100 || version > 0x0120 || length < 0x20 || (length & 3) || !slots || !ports ||
        !(hcs1 & 0x7ff00) || length + port_base + ports * port_stride > span ||
        doorbell < length + 0x3c || doorbell > span - (slots + 1) * 4 || runtime < length + 0x3c ||
        runtime > span - 0x40 || scratchpads > max_scratchpads || !quiet_interrupts(pci) ||
        !claim_firmware(base, span, hcc)) {
        pci.write16(4, original);
        log("xhci: probe rejected pci=%x:%x.%x\n", uint64_t(pci.bus), uint64_t(pci.slot),
            uint64_t(pci.function));
        return;
    }
    Controller controller{base + length / 4,   base + (runtime + interrupter_zero) / 4,
                          base + doorbell / 4, slots,
                          scratchpads,         hcc & 4 ? 16u : 8u};
    pci.write16(4, (original & ~7u) | pci_memory | pci_master | pci_intx_disable);
    unsigned completed = 0, connected = 0;
    if ((pci.read16(4) & (pci_memory | pci_master)) == (pci_memory | pci_master) &&
        controller.initialize()) {
        while (completed < commands_to_check && controller.command())
            ++completed;
        for (unsigned i = 0; i < ports; ++i) {
            if (!(read(controller.operational, port_base + i * port_stride) & port_connected))
                continue;
            ++connected;
            if (completed == commands_to_check && !controller.probe_device(i + 1))
                log("xhci: could not read device descriptor on port %u\n", uint64_t(i + 1));
        }
    }
    const bool stopped = controller.stop();
    pci.write16(4, (original & ~pci_master) | pci_intx_disable);
    if (controller.dma && stopped) {
        for (uint64_t device : controller.devices)
            if (device)
                page_free(device, device_pages);
        page_free(controller.dma, controller.pages());
    }
    log("xhci: pci=%x:%x.%x commands=%u ports=%u connected=%u stopped=%u\n", uint64_t(pci.bus),
        uint64_t(pci.slot), uint64_t(pci.function), uint64_t(completed), uint64_t(ports),
        uint64_t(connected), uint64_t(stopped));
}
} // namespace

void xhci_probe() {
    visited = 0;
    pci_scan(probe);
}
} // namespace ax
