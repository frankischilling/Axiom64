// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/usb/xhci.cpp
 * @brief   xHCI root device probing and HID boot input.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Claims a PCI controller, reads root device descriptors, and dispatches
 * boot keyboard and mouse reports to the console and input devices.
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
#include "drivers/platform/devices.hpp"
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
constexpr unsigned root_port_detection_ticks = 25;
constexpr unsigned intel_reset_delay_us = 1000;
constexpr unsigned descriptor_size = 18, device_pages = 5, keyboard_report_size = 8;
constexpr unsigned max_input_devices = 8, keyboard_codes = 128, mouse_report_size = 3;
constexpr unsigned configuration_header_size = 9;
constexpr unsigned enable_slot = 9, address_device = 11, configure_endpoint = 12,
                   evaluate_context = 13, no_op = 23, transfer_event = 32, command_event = 33,
                   port_event = 34;
constexpr uint32_t port_connected = 1, port_enabled = 2, port_reset = 1 << 4;
constexpr uint32_t port_configuration = (1 << 9) | (3 << 14) | (7 << 25);
uint8_t held_keys[keyboard_codes], held_buttons[3];

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

enum class BootProtocol { none, keyboard, mouse };

unsigned report_size(BootProtocol protocol) {
    return protocol == BootProtocol::keyboard ? keyboard_report_size : mouse_report_size;
}

struct BootEndpoint {
    unsigned interface, address, packet, interval;
    BootProtocol protocol;
};

enum class ProbeMode { describe, check_keyboard, keyboard };

unsigned boot_key(unsigned usage) {
    constexpr uint8_t letters[] = {30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50,
                                   49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44};
    constexpr uint8_t controls[] = {
        28,  1,   14,  15, 57, 12, 13, 26, 27, 43, 86, 39, 40,  41,  51,  52,  53,  58,  59,  60,
        61,  62,  63,  64, 65, 66, 67, 68, 87, 88, 99, 70, 119, 110, 102, 104, 111, 107, 109, 106,
        105, 108, 103, 69, 98, 55, 74, 78, 96, 79, 80, 81, 75,  76,  77,  71,  72,  73,  82,  83};
    if (usage >= 4 && usage <= 29)
        return letters[usage - 4];
    if (usage >= 30 && usage <= 39)
        return usage - 28;
    return usage >= 40 && usage < 40 + sizeof(controls) ? controls[usage - 40] : 0;
}

bool has_usage(const uint8_t* bytes, unsigned count, unsigned wanted) {
    for (unsigned i = 0; i < count; ++i)
        if (bytes[i] == wanted)
            return true;
    return false;
}

void keyboard_report(uint8_t* previous, const uint8_t* next, uint8_t* held) {
    constexpr uint8_t modifiers[] = {29, 42, 56, 125, 97, 54, 100, 126};
    for (unsigned i = 2; i < keyboard_report_size; ++i)
        if (next[i] && next[i] < 4)
            return;
    const auto dispatch_key = [held](unsigned code, bool pressed) {
        // Only a first press or the last release changes the shared input state.
        if (pressed ? held[code]++ == 0 : --held[code] == 0)
            usb_keyboard_event(code, pressed);
    };
    for (unsigned i = 0; i < sizeof(modifiers); ++i)
        if ((previous[0] ^ next[0]) & (1u << i))
            dispatch_key(modifiers[i], (next[0] >> i) & 1);
    const auto dispatch = [&](const uint8_t* source, const uint8_t* other, bool pressed) {
        for (unsigned i = 2; i < keyboard_report_size; ++i) {
            const auto usage = source[i];
            const auto code = boot_key(usage);
            if (code && !has_usage(other + 2, keyboard_report_size - 2, usage) &&
                !has_usage(source + 2, i - 2, usage))
                dispatch_key(code, pressed);
        }
    };
    dispatch(previous, next, false);
    dispatch(next, previous, true);
    memcpy(previous, next, keyboard_report_size);
}

unsigned descriptor_word(const uint8_t* bytes) {
    return bytes[0] | (bytes[1] << 8);
}

bool parse_configuration(const uint8_t* bytes, unsigned length, BootEndpoint& input) {
    if (bytes[0] != configuration_header_size || bytes[1] != 2 ||
        descriptor_word(bytes + 2) != length || !bytes[5])
        return false;
    BootProtocol protocol = BootProtocol::none;
    unsigned interface = 0;
    for (unsigned offset = configuration_header_size; offset < length;) {
        const auto item = bytes + offset;
        if (length - offset < 2 || item[0] < 2 || item[0] > length - offset)
            return false;
        if (item[1] == 4) {
            if (item[0] < 9)
                return false;
            interface = item[2];
            protocol = BootProtocol::none;
            if (!item[3] && item[4] && item[5] == 3 && item[6] == 1) {
                if (item[7] == 1)
                    protocol = BootProtocol::keyboard;
                else if (item[7] == 2)
                    protocol = BootProtocol::mouse;
            }
        } else if (item[1] == 5) {
            if (item[0] < 7)
                return false;
            const unsigned packet = descriptor_word(item + 4) & 0x7ff;
            const bool preferred = !input.address || (input.protocol == BootProtocol::mouse &&
                                                      protocol == BootProtocol::keyboard);
            if (protocol != BootProtocol::none && preferred && (item[2] & 0x80) && (item[2] & 15) &&
                !(item[2] & 0x70) && (item[3] & 3) == 3 && packet >= report_size(protocol) &&
                item[6])
                input = {interface, item[2], packet, item[6], protocol};
        }
        offset += item[0];
    }
    return true;
}

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

    struct InputDevice {
        unsigned slot = 0, port = 0, endpoint = 0, index = 0, cycle = 1;
        BootProtocol protocol = BootProtocol::none;
        uint8_t previous[keyboard_report_size]{};
    };

    InputDevice inputs[max_input_devices]{};
    unsigned input_count = 0;

    unsigned pages() const {
        return scratchpads ? 5 + scratchpads : 4;
    }

    bool stop() const {
        write(operational, command_reg,
              read(operational, command_reg) & ~(run | interrupt_enable | host_error_enable));
        return DevicePoll::wait([&] { return read(operational, status_reg) & halted; },
                                timeout_ticks);
    }

    bool initialize(bool intel) {
        if (!DevicePoll::wait([&] { return !(read(operational, status_reg) & not_ready); },
                              timeout_ticks) ||
            !stop())
            return false;
        write(operational, command_reg, reset);
        // Intel xHCI controllers need a quiet interval after asserting HCRST.
        if (intel && !clock_delay_us(intel_reset_delay_us))
            return false;
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

    bool next_event(Trb& result) {
        auto events = static_cast<volatile Trb*>(physical(dma + 2 * page_size));
        const auto control = events[event_index].control;
        if ((control & 1) != event_cycle)
            return false;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        result = {events[event_index].parameter, events[event_index].status, control};
        if (++event_index == ring_size) {
            event_index = 0;
            event_cycle ^= 1;
        }
        write_address(interrupter, erdp, (dma + 2 * page_size + event_index * sizeof(Trb)) | 8);
        return true;
    }

    bool completion(uint64_t expected, unsigned type, Trb& result,
                    unsigned timeout = timeout_ticks) {
        bool success = false;
        bool complete = DevicePoll::wait(
            [&] {
                if (read(operational, status_reg) & (halted | host_error))
                    return true;
                if (!next_event(result))
                    return false;
                const auto event_type = (result.control >> 10) & 63;
                if (event_type == port_event) // Port status remains available in PORTSC.
                    return false;
                success = event_type == type && result.parameter == expected &&
                          (result.status >> 24) == 1;
                return true;
            },
            timeout);
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

    bool control_transfer(unsigned slot, unsigned first, uint64_t request, unsigned length) {
        if (length > page_size || first > ring_size - 4)
            return false;
        const uint64_t transfer = devices[slot] + 2 * page_size;
        auto ring = static_cast<volatile Trb*>(physical(transfer));
        constexpr uint32_t setup = (2 << 10) | (1 << 6);
        constexpr uint32_t data_in = (3 << 10) | (1 << 16);
        constexpr uint32_t status = (4 << 10) | (1 << 5);
        ring[first].parameter = (uint64_t(length) << 48) | request;
        ring[first].status = 8;
        unsigned last = first + 1;
        if (length) {
            ring[last].parameter = devices[slot] + 3 * page_size;
            memset(physical(ring[last].parameter), 0, length);
            ring[last].status = length;
            ring[last++].control = data_in | 1;
        }
        ring[last].parameter = 0;
        ring[last].status = 0;
        ring[last].control = status | (length ? 0u : (1 << 16)) | 1;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        ring[first].control = setup | (length ? (3 << 16) : 0u) | 1;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        write(doorbell, slot * 4, 1); // Endpoint zero has device-context index 1.
        Trb event{};
        return completion(transfer + last * sizeof(Trb), transfer_event, event) &&
               (event.control >> 24) == slot && ((event.control >> 16) & 31) == 1;
    }

    bool read_descriptor(unsigned slot, unsigned first, unsigned type, unsigned length) {
        return control_transfer(slot, first, (uint64_t(type) << 24) | 0x0680, length);
    }

    bool configure_input_endpoint(unsigned slot, const BootEndpoint& descriptor, unsigned speed,
                                  unsigned dci, uint64_t ring) {
        if (speed >= 3 && descriptor.interval > 16)
            return false;
        const unsigned interval =
            speed >= 3 ? descriptor.interval - 1 : 31 - __builtin_clz(8u * descriptor.interval);
        // HID SET_PROTOCOL selects the fixed boot report for the interface.
        if (!control_transfer(slot, 17, (uint64_t(descriptor.interface) << 32) | 0x0b21, 0))
            return false;
        const uint64_t input = devices[slot];
        auto contexts = static_cast<uint32_t*>(physical(input));
        auto slot_context = contexts + context_words;
        const auto output_slot = static_cast<const uint32_t*>(physical(input + page_size));
        memset(contexts, 0, page_size);
        memcpy(slot_context, output_slot, context_words * sizeof(uint32_t));
        contexts[1] = (1u << dci) | 1;
        slot_context[0] = (slot_context[0] & ~(31u << 27)) | (dci << 27);
        slot_context[3] = 0;
        auto endpoint = contexts + (dci + 1) * context_words;
        endpoint[0] = interval << 16;
        endpoint[1] = (descriptor.packet << 16) | (7 << 3) | (3 << 1);
        endpoint[2] = uint32_t(ring) | 1;
        endpoint[3] = ring >> 32;
        endpoint[4] = (descriptor.packet << 16) | report_size(descriptor.protocol);
        return command(configure_endpoint, input, slot);
    }

    bool probe_keyboard_reports(unsigned slot, unsigned port, unsigned speed,
                                const BootEndpoint& keyboard) {
        constexpr unsigned reports_to_check = 16, report_timeout = 500;
        constexpr uint32_t normal_ioc = (1 << 10) | (1 << 5);
        const unsigned dci = 2 * (keyboard.address & 15) + 1;
        const uint64_t ring_address = devices[slot] + 4 * page_size;
        if (!configure_input_endpoint(slot, keyboard, speed, dci, ring_address))
            return false;
        const uint64_t buffer = devices[slot] + 3 * page_size;
        auto bytes = static_cast<const uint8_t*>(physical(buffer));
        auto ring = static_cast<volatile Trb*>(physical(ring_address));
        unsigned usage = 0;
        for (unsigned i = 0; i < reports_to_check; ++i) {
            ring[i].parameter = buffer;
            ring[i].status = keyboard_report_size;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            ring[i].control = normal_ioc | 1;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            write(doorbell, slot * 4, dci);
            if (!i)
                log("xhci-keyboard-ready: port=%u\n", uint64_t(port));
            Trb event{};
            if (!completion(ring_address + i * sizeof(Trb), transfer_event, event,
                            report_timeout) ||
                (event.control >> 24) != slot || ((event.control >> 16) & 31) != dci ||
                (event.status & 0xffffff))
                return false;
            unsigned first_usage = 0;
            bool valid = true, still_pressed = false;
            for (unsigned key = 2; key < keyboard_report_size; ++key) {
                const unsigned code = bytes[key];
                if (!code)
                    continue;
                if (code < 4) {
                    valid = false; // HID error reports do not describe the held keys.
                    break;
                }
                if (!first_usage)
                    first_usage = code;
                still_pressed |= code == usage;
            }
            if (!valid)
                continue;
            if (usage && !still_pressed) {
                log("xhci-key: port=%u usage=%u pressed=0\n", uint64_t(port), uint64_t(usage));
                return true;
            }
            if (!usage && first_usage) {
                usage = first_usage;
                log("xhci-key: port=%u usage=%u pressed=1\n", uint64_t(port), uint64_t(usage));
            }
        }
        return false;
    }

    uint64_t input_ring(const InputDevice& input) const {
        return devices[input.slot] + 4 * page_size;
    }

    void queue_input(const InputDevice& input) {
        constexpr uint32_t normal_ioc = (1u << 10) | (1u << 5), link_toggle = (6u << 10) | 2;
        const auto address = input_ring(input);
        auto ring = static_cast<volatile Trb*>(physical(address));
        if (input.index + 2 == ring_size) {
            auto& tail = ring[ring_size - 1];
            tail.parameter = address;
            tail.status = 0;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            tail.control = link_toggle | input.cycle;
        }
        auto& trb = ring[input.index];
        trb.parameter = devices[input.slot] + 3 * page_size;
        trb.status = report_size(input.protocol);
        __atomic_thread_fence(__ATOMIC_RELEASE);
        trb.control = normal_ioc | input.cycle;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        write(doorbell, input.slot * 4, input.endpoint);
    }

    bool start_input(unsigned slot, unsigned port, unsigned speed, const BootEndpoint& descriptor) {
        const unsigned endpoint = 2 * (descriptor.address & 15) + 1;
        if (input_count == max_input_devices ||
            !configure_input_endpoint(slot, descriptor, speed, endpoint,
                                      devices[slot] + 4 * page_size))
            return false;
        auto& input = inputs[input_count++];
        input.slot = slot;
        input.port = port;
        input.endpoint = endpoint;
        input.protocol = descriptor.protocol;
        return true;
    }

    void input_report(InputDevice& input, const uint8_t* report) {
        if (input.protocol == BootProtocol::keyboard) {
            keyboard_report(input.previous, report, held_keys);
            return;
        }
        uint8_t buttons = 0;
        for (unsigned i = 0; i < sizeof(held_buttons); ++i) {
            const uint8_t mask = 1u << i;
            if ((input.previous[0] ^ report[0]) & mask)
                held_buttons[i] += report[0] & mask ? 1 : -1;
            if (held_buttons[i])
                buttons |= mask;
        }
        input.previous[0] = report[0] & 7;
        usb_mouse_event(int8_t(report[1]), int8_t(report[2]), buttons);
    }

    void disconnect_input(InputDevice& input) {
        uint8_t empty[keyboard_report_size]{};
        input_report(input, empty);
        log("xhci-%s-stopped: port=%u\n",
            input.protocol == BootProtocol::keyboard ? "keyboard" : "mouse", uint64_t(input.port));
        input.slot = 0;
    }

    void complete_input(InputDevice& input, const Trb& event) {
        if (event.parameter != input_ring(input) + input.index * sizeof(Trb) ||
            (event.status != (1u << 24) && (event.status >> 24) != 13)) {
            disconnect_input(input);
            return;
        }
        if (event.status == (1u << 24)) {
            const auto data =
                static_cast<const uint8_t*>(physical(devices[input.slot] + 3 * page_size));
            input_report(input, data);
        }
        if (++input.index == ring_size - 1) {
            input.index = 0;
            input.cycle ^= 1;
        }
        queue_input(input);
    }

    void poll_input() {
        if (!input_count)
            return;
        const bool failed = read(operational, status_reg) & (halted | host_error);
        for (unsigned i = 0; i < input_count; ++i) {
            auto& input = inputs[i];
            const auto port = port_base + (input.port - 1) * port_stride;
            if (input.slot && (failed || !(read(operational, port) & port_connected)))
                disconnect_input(input);
        }
        if (failed)
            return;
        Trb event{};
        for (unsigned count = 0; count < 8 && next_event(event); ++count) {
            if (((event.control >> 10) & 63) != transfer_event)
                continue;
            for (unsigned i = 0; i < input_count; ++i) {
                auto& input = inputs[i];
                if (input.slot && (event.control >> 24) == input.slot &&
                    ((event.control >> 16) & 31) == input.endpoint) {
                    complete_input(input, event);
                    break;
                }
            }
        }
    }

    bool probe_configuration(unsigned slot, unsigned port, unsigned speed, ProbeMode mode) {
        auto bytes = static_cast<const uint8_t*>(physical(devices[slot] + 3 * page_size));
        if (!read_descriptor(slot, 6, 2, configuration_header_size))
            return false;
        const unsigned length = descriptor_word(bytes + 2);
        if (bytes[0] != configuration_header_size || bytes[1] != 2 ||
            length < configuration_header_size || length > page_size ||
            !read_descriptor(slot, 9, 2, length))
            return false;
        BootEndpoint input{};
        if (!parse_configuration(bytes, length, input))
            return false;
        if (!input.address ||
            (mode == ProbeMode::check_keyboard && input.protocol != BootProtocol::keyboard))
            return true;
        const unsigned value = bytes[5];
        if (!control_transfer(slot, 12, (uint64_t(value) << 16) | 0x0900, 0) ||
            !control_transfer(slot, 14, 0x0880, 1) || bytes[0] != value)
            return false;
        log("xhci-%s: port=%u configuration=%u interface=%u endpoint=%x packet=%u "
            "interval=%u\n",
            input.protocol == BootProtocol::keyboard ? "keyboard" : "mouse", uint64_t(port),
            uint64_t(value), uint64_t(input.interface), uint64_t(input.address),
            uint64_t(input.packet), uint64_t(input.interval));
        if (mode == ProbeMode::keyboard)
            return start_input(slot, port, speed, input);
        return mode != ProbeMode::check_keyboard ||
               probe_keyboard_reports(slot, port, speed, input);
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

    bool probe_device(unsigned port, ProbeMode mode) {
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
        if (!command(address_device, input, slot) || !read_descriptor(slot, 0, 1, 8))
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
        if (!read_descriptor(slot, 3, 1, descriptor_size) || descriptor[0] != descriptor_size ||
            descriptor[1] != 1 || !descriptor[17])
            return false;
        log("xhci-device: port=%u speed=%u vendor=%x product=%x configurations=%u\n",
            uint64_t(port), uint64_t(speed), uint64_t(descriptor[8] | (descriptor[9] << 8)),
            uint64_t(descriptor[10] | (descriptor[11] << 8)), uint64_t(descriptor[17]));
        return probe_configuration(slot, port, speed, mode);
    }
};

unsigned visited;
ProbeMode probe_mode;

struct RuntimeController {
    Controller controller;
    PciFunction pci;
    uint16_t original;
};

RuntimeController active_controllers[max_controllers];
unsigned active_count;

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
        controller.initialize(pci.read16(0) == 0x8086)) {
        // Powered ports can still be detecting connected devices after Run.
        clock_refresh();
        const uint64_t started = ticks;
        DevicePoll::wait([&] { return ticks - started >= root_port_detection_ticks; },
                         root_port_detection_ticks + 1);
        if (probe_mode != ProbeMode::keyboard)
            while (completed < commands_to_check && controller.command())
                ++completed;
        for (unsigned i = 0; i < ports; ++i) {
            if (!(read(controller.operational, port_base + i * port_stride) & port_connected))
                continue;
            ++connected;
            if ((probe_mode == ProbeMode::keyboard || completed == commands_to_check) &&
                !controller.probe_device(i + 1, probe_mode))
                log("xhci: root port %u probe incomplete\n", uint64_t(i + 1));
        }
        if (controller.input_count &&
            !(read(controller.operational, status_reg) & (halted | host_error))) {
            auto& active = active_controllers[active_count++];
            active = {controller, pci, original};
            // Finish command and control transfers before queuing input on any slot.
            for (unsigned i = 0; i < active.controller.input_count; ++i) {
                const auto& input = active.controller.inputs[i];
                active.controller.queue_input(input);
                log("xhci-%s-active: port=%u\n",
                    input.protocol == BootProtocol::keyboard ? "keyboard" : "mouse",
                    uint64_t(input.port));
            }
            return;
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

void xhci_probe(bool keyboard_reports) {
    visited = 0;
    probe_mode = keyboard_reports ? ProbeMode::check_keyboard : ProbeMode::describe;
    pci_scan(probe);
}

void xhci_keyboard_init() {
    visited = 0;
    probe_mode = ProbeMode::keyboard;
    pci_scan(probe);
}

void xhci_keyboard_poll() {
    for (unsigned i = 0; i < active_count; ++i)
        active_controllers[i].controller.poll_input();
}

bool xhci_keyboard_shutdown() {
    bool success = true;
    for (unsigned i = 0; i < active_count; ++i) {
        auto& active = active_controllers[i];
        auto& controller = active.controller;
        const bool stopped = controller.stop();
        active.pci.write16(4, (active.original & ~pci_master) | pci_intx_disable);
        if (stopped) {
            for (const auto device : controller.devices)
                if (device)
                    page_free(device, device_pages);
            page_free(controller.dma, controller.pages());
        }
        success &= stopped;
    }
    active_count = 0;
    return success;
}
} // namespace ax
