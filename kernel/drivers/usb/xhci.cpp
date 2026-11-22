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
#include "drivers/usb/hid_keyboard.hpp"
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
constexpr unsigned enable_slot = 9, disable_slot = 10, address_device = 11, configure_endpoint = 12,
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

struct BootEndpoints {
    BootEndpoint keyboard, mouse;
};

struct ReportEndpoint {
    BootEndpoint endpoint;
    unsigned descriptor_bytes;
};

constexpr HidKeyboardLayout boot_keyboard_layout{0, 0, 2, 6, keyboard_report_size};

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

void keyboard_report(uint8_t& previous_modifiers, uint8_t* previous, uint8_t next_modifiers,
                     const uint8_t* next, unsigned count) {
    constexpr uint8_t modifiers[] = {29, 42, 56, 125, 97, 54, 100, 126};
    for (unsigned i = 0; i < count; ++i)
        if (next[i] && next[i] < 4)
            return;
    const auto dispatch_key = [](unsigned code, bool pressed) {
        // Only a first press or the last release changes the shared input state.
        if (pressed ? held_keys[code]++ == 0 : --held_keys[code] == 0)
            usb_keyboard_event(code, pressed);
    };
    for (unsigned i = 0; i < sizeof(modifiers); ++i)
        if ((previous_modifiers ^ next_modifiers) & (1u << i))
            dispatch_key(modifiers[i], (next_modifiers >> i) & 1);
    const auto dispatch = [&](const uint8_t* source, const uint8_t* other, bool pressed) {
        for (unsigned i = 0; i < count; ++i) {
            const auto usage = source[i];
            const auto code = boot_key(usage);
            if (code && !has_usage(other, count, usage) && !has_usage(source, i, usage))
                dispatch_key(code, pressed);
        }
    };
    dispatch(previous, next, false);
    dispatch(next, previous, true);
    previous_modifiers = next_modifiers;
    memcpy(previous, next, count);
}

unsigned descriptor_word(const uint8_t* bytes) {
    return bytes[0] | (bytes[1] << 8);
}

bool parse_configuration(const uint8_t* bytes, unsigned length, BootEndpoints& boot,
                         ReportEndpoint& report) {
    if (bytes[0] != configuration_header_size || bytes[1] != 2 ||
        descriptor_word(bytes + 2) != length || !bytes[5])
        return false;
    BootProtocol protocol = BootProtocol::none;
    unsigned interface = 0;
    bool report_interface = false;
    unsigned report_bytes = 0;
    for (unsigned offset = configuration_header_size; offset < length;) {
        const auto item = bytes + offset;
        if (length - offset < 2 || item[0] < 2 || item[0] > length - offset)
            return false;
        if (item[1] == 4) {
            if (item[0] < 9)
                return false;
            interface = item[2];
            report_interface = !item[3] && item[4] && item[5] == 3 && !item[6] && item[7] <= 1;
            report_bytes = 0;
            protocol = BootProtocol::none;
            if (!item[3] && item[4] && item[5] == 3 && item[6] == 1) {
                if (item[7] == 1)
                    protocol = BootProtocol::keyboard;
                else if (item[7] == 2)
                    protocol = BootProtocol::mouse;
            }
        } else if (item[1] == 0x21 && report_interface && item[0] >= 9 && item[6] == 0x22) {
            report_bytes = descriptor_word(item + 7);
        } else if (item[1] == 5) {
            if (item[0] < 7)
                return false;
            const unsigned packet = descriptor_word(item + 4) & 0x7ff;
            const bool interrupt_in = (item[2] & 0x80) && (item[2] & 15) && !(item[2] & 0x70) &&
                                      (item[3] & 3) == 3 && item[6];
            if (report_interface && report_bytes && report_bytes <= 512 &&
                !report.descriptor_bytes && interrupt_in && packet && packet <= 1024)
                report = {{interface, item[2], packet, item[6], BootProtocol::keyboard},
                          report_bytes};
            auto& input = protocol == BootProtocol::keyboard ? boot.keyboard : boot.mouse;
            if (protocol != BootProtocol::none && !input.address && interrupt_in &&
                packet >= report_size(protocol) && packet <= 1024)
                input = {interface, item[2], packet, item[6], protocol};
        }
        offset += item[0];
    }
    return !boot.keyboard.address || !boot.mouse.address ||
           boot.keyboard.address != boot.mouse.address;
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

void wait_usb_recovery() {
    clock_refresh();
    const auto start = ticks;
    DevicePoll::wait([&] { return ticks - start >= 2; }, 3);
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
    uint64_t additional_input_pages[256][2]{};
    unsigned control_next[256]{};

    struct InputDevice {
        unsigned slot = 0, port = 0, endpoint = 0, index = 0, cycle = 1;
        BootProtocol protocol = BootProtocol::none;
        uint64_t buffer = 0, ring = 0;
        unsigned transfer_bytes = 0;
        HidKeyboardLayout layout{};
        uint8_t previous_flags = 0, previous_keys[max_hid_keyboard_keys]{};
    };

    InputDevice inputs[max_input_devices]{};
    unsigned input_count = 0;

    unsigned pages() const {
        return scratchpads ? 5 + scratchpads : 4;
    }

    void release_dma() const {
        for (unsigned slot = 1; slot <= slots; ++slot) {
            for (auto page : additional_input_pages[slot])
                if (page)
                    page_free(page, 2);
            if (devices[slot])
                page_free(devices[slot], device_pages);
        }
        page_free(dma, pages());
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

    bool control_transfer(unsigned slot, uint64_t request, unsigned length,
                          unsigned* completion_code = nullptr) {
        const unsigned first = control_next[slot];
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
        control_next[slot] = last + 1;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        ring[first].control = setup | (length ? (3 << 16) : 0u) | 1;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        write(doorbell, slot * 4, 1); // Endpoint zero has device-context index 1.
        Trb event{};
        const bool success = completion(transfer + last * sizeof(Trb), transfer_event, event);
        const bool same_endpoint =
            (event.control >> 24) == slot && ((event.control >> 16) & 31) == 1;
        if (completion_code && same_endpoint && ((event.control >> 10) & 63) == transfer_event &&
            event.parameter >= transfer + first * sizeof(Trb) &&
            event.parameter <= transfer + last * sizeof(Trb))
            *completion_code = event.status >> 24;
        return success && same_endpoint;
    }

    bool read_descriptor(unsigned slot, unsigned type, unsigned length) {
        return control_transfer(slot, (uint64_t(type) << 24) | 0x0680, length);
    }

    bool configure_input_endpoint(unsigned slot, const BootEndpoint& descriptor, unsigned speed,
                                  unsigned dci, uint64_t ring, unsigned report_bytes,
                                  bool boot_protocol) {
        if (speed >= 3 && descriptor.interval > 16)
            return false;
        const unsigned interval =
            speed >= 3 ? descriptor.interval - 1 : 31 - __builtin_clz(8u * descriptor.interval);
        // HID SET_PROTOCOL selects the fixed boot report for the interface.
        if (boot_protocol &&
            !control_transfer(slot, (uint64_t(descriptor.interface) << 32) | 0x0b21, 0))
            return false;
        const uint64_t input = devices[slot];
        auto contexts = static_cast<uint32_t*>(physical(input));
        auto slot_context = contexts + context_words;
        const auto output_slot = static_cast<const uint32_t*>(physical(input + page_size));
        memset(contexts, 0, page_size);
        memcpy(slot_context, output_slot, context_words * sizeof(uint32_t));
        contexts[1] = (1u << dci) | 1;
        const unsigned last_endpoint = max(dci, slot_context[0] >> 27);
        slot_context[0] = (slot_context[0] & ~(31u << 27)) | (last_endpoint << 27);
        slot_context[3] = 0;
        auto endpoint = contexts + (dci + 1) * context_words;
        endpoint[0] = interval << 16;
        endpoint[1] = (descriptor.packet << 16) | (7 << 3) | (3 << 1);
        endpoint[2] = uint32_t(ring) | 1;
        endpoint[3] = ring >> 32;
        endpoint[4] = (descriptor.packet << 16) | report_bytes;
        return command(configure_endpoint, input, slot);
    }

    bool probe_keyboard_reports(unsigned slot, unsigned port, unsigned speed,
                                const BootEndpoint& keyboard) {
        constexpr unsigned reports_to_check = 16, report_timeout = 500;
        constexpr uint32_t normal_ioc = (1 << 10) | (1 << 5);
        const unsigned dci = 2 * (keyboard.address & 15) + 1;
        const uint64_t ring_address = devices[slot] + 4 * page_size;
        if (!configure_input_endpoint(slot, keyboard, speed, dci, ring_address,
                                      keyboard_report_size, true))
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

    void queue_input(const InputDevice& input) {
        constexpr uint32_t normal_ioc = (1u << 10) | (1u << 5) | (1u << 2);
        constexpr uint32_t link_toggle = (6u << 10) | 2;
        const auto address = input.ring;
        auto ring = static_cast<volatile Trb*>(physical(address));
        if (input.index + 2 == ring_size) {
            auto& tail = ring[ring_size - 1];
            tail.parameter = address;
            tail.status = 0;
            __atomic_thread_fence(__ATOMIC_RELEASE);
            tail.control = link_toggle | input.cycle;
        }
        auto& trb = ring[input.index];
        trb.parameter = input.buffer;
        trb.status = input.transfer_bytes;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        trb.control = normal_ioc | input.cycle;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        write(doorbell, input.slot * 4, input.endpoint);
    }

    bool start_input(unsigned slot, unsigned port, unsigned speed, const BootEndpoint& descriptor,
                     bool second_boot_endpoint) {
        if (input_count == max_input_devices)
            return false;
        const unsigned endpoint = 2 * (descriptor.address & 15) + 1;
        auto buffer = devices[slot] + 3 * page_size;
        if (second_boot_endpoint) {
            buffer = Dma::allocate(2, Dma::pci);
            if (!buffer)
                return false;
            additional_input_pages[slot][0] = buffer;
        }
        const unsigned wanted = report_size(descriptor.protocol);
        if (!configure_input_endpoint(slot, descriptor, speed, endpoint, buffer + page_size, wanted,
                                      true))
            return false;
        auto& input = inputs[input_count++];
        input.slot = slot;
        input.port = port;
        input.endpoint = endpoint;
        input.protocol = descriptor.protocol;
        input.buffer = buffer;
        input.ring = buffer + page_size;
        input.transfer_bytes = descriptor.packet;
        if (input.protocol == BootProtocol::keyboard)
            input.layout = boot_keyboard_layout;
        return true;
    }

    void start_report_keyboard(unsigned slot, unsigned port, unsigned speed,
                               const ReportEndpoint& report) {
        const auto& descriptor = report.endpoint;
        const unsigned endpoint = 2 * (descriptor.address & 15) + 1;
        if (input_count == max_input_devices)
            return;
        for (unsigned i = 0; i < input_count; ++i)
            if (inputs[i].slot == slot && inputs[i].endpoint == endpoint)
                return;
        const uint64_t request = (uint64_t(descriptor.interface) << 32) | 0x22000681;
        if (!control_transfer(slot, request, report.descriptor_bytes))
            return;
        const auto bytes = static_cast<const uint8_t*>(physical(devices[slot] + 3 * page_size));
        HidKeyboardLayout layout{};
        if (!hid_keyboard_layout(bytes, report.descriptor_bytes, layout) ||
            layout.bytes > descriptor.packet)
            return;
        // Report-mode keyboards can use event-driven idle reporting.
        control_transfer(slot, (uint64_t(descriptor.interface) << 32) | 0x0a21, 0);
        const auto buffer = Dma::allocate(2, Dma::pci);
        additional_input_pages[slot][1] = buffer;
        if (!buffer || !configure_input_endpoint(slot, descriptor, speed, endpoint,
                                                 buffer + page_size, layout.bytes, false))
            return;
        auto& input = inputs[input_count++];
        input.slot = slot;
        input.port = port;
        input.endpoint = endpoint;
        input.protocol = BootProtocol::keyboard;
        input.buffer = buffer;
        input.ring = buffer + page_size;
        input.transfer_bytes = descriptor.packet;
        input.layout = layout;
        log("xhci-report-keyboard: port=%u interface=%u report=%u keys=%u bytes=%u\n",
            uint64_t(port), uint64_t(descriptor.interface), uint64_t(layout.report_id),
            uint64_t(layout.key_count), uint64_t(layout.bytes));
    }

    void input_report(InputDevice& input, const uint8_t* report) {
        if (input.protocol == BootProtocol::keyboard) {
            keyboard_report(input.previous_flags, input.previous_keys,
                            report[input.layout.modifiers], report + input.layout.keys,
                            input.layout.key_count);
            return;
        }
        uint8_t buttons = 0;
        for (unsigned i = 0; i < sizeof(held_buttons); ++i) {
            const uint8_t mask = 1u << i;
            if ((input.previous_flags ^ report[0]) & mask)
                held_buttons[i] += report[0] & mask ? 1 : -1;
            if (held_buttons[i])
                buttons |= mask;
        }
        input.previous_flags = report[0] & 7;
        usb_mouse_event(int8_t(report[1]), int8_t(report[2]), buttons);
    }

    void disconnect_input(InputDevice& input) {
        uint8_t empty[65]{};
        input_report(input, empty);
        log("xhci-%s-stopped: port=%u\n",
            input.protocol == BootProtocol::keyboard ? "keyboard" : "mouse", uint64_t(input.port));
        input.slot = 0;
    }

    void complete_input(InputDevice& input, const Trb& event) {
        const unsigned code = event.status >> 24, remaining = event.status & 0xffffff;
        if (event.parameter != input.ring + input.index * sizeof(Trb) ||
            (code != 1 && code != 13) || remaining > input.transfer_bytes) {
            disconnect_input(input);
            return;
        }
        const unsigned actual = input.transfer_bytes - remaining;
        // Boot mice can append device-specific bytes after the three standard bytes.
        const bool complete_report = input.protocol == BootProtocol::mouse
                                         ? actual >= mouse_report_size
                                         : actual == input.layout.bytes;
        const auto data = static_cast<const uint8_t*>(physical(input.buffer));
        if (complete_report && (!input.layout.report_id || data[0] == input.layout.report_id))
            input_report(input, data);
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

    bool probe_configuration(unsigned slot, unsigned port, unsigned speed, ProbeMode mode,
                             bool full_descriptor_read) {
        auto bytes = static_cast<const uint8_t*>(physical(devices[slot] + 3 * page_size));
        // Some devices return a full packet even when only a descriptor header was requested.
        if (!read_descriptor(slot, 2, full_descriptor_read ? page_size : configuration_header_size))
            return false;
        const unsigned length = descriptor_word(bytes + 2);
        if (bytes[0] != configuration_header_size || bytes[1] != 2 ||
            length < configuration_header_size || length > page_size ||
            (!full_descriptor_read && !read_descriptor(slot, 2, length)))
            return false;
        BootEndpoints boot{};
        ReportEndpoint report{};
        if (!parse_configuration(bytes, length, boot, report))
            return false;
        const bool runtime = mode == ProbeMode::keyboard;
        if ((!boot.keyboard.address && !boot.mouse.address &&
             !(runtime && report.descriptor_bytes)) ||
            (mode == ProbeMode::check_keyboard && !boot.keyboard.address))
            return true;
        const unsigned value = bytes[5];
        if (!control_transfer(slot, (uint64_t(value) << 16) | 0x0900, 0) ||
            !control_transfer(slot, 0x0880, 1) || bytes[0] != value)
            return false;
        bool second_boot_endpoint = false;
        const BootEndpoint* endpoints[] = {&boot.keyboard, &boot.mouse};
        for (const auto input : endpoints) {
            if (!input->address)
                continue;
            log("xhci-%s: port=%u configuration=%u interface=%u endpoint=%x packet=%u "
                "interval=%u\n",
                input->protocol == BootProtocol::keyboard ? "keyboard" : "mouse", uint64_t(port),
                uint64_t(value), uint64_t(input->interface), uint64_t(input->address),
                uint64_t(input->packet), uint64_t(input->interval));
            if (runtime) {
                if (!start_input(slot, port, speed, *input, second_boot_endpoint))
                    return false;
                second_boot_endpoint = true;
            }
        }
        if (runtime) {
            if (report.descriptor_bytes)
                start_report_keyboard(slot, port, speed, report);
            return true;
        }
        return mode != ProbeMode::check_keyboard ||
               probe_keyboard_reports(slot, port, speed, boot.keyboard);
    }

    bool enable_port(unsigned port, unsigned& speed, bool force_reset) {
        unsigned offset = port_base + (port - 1) * port_stride;
        uint32_t status = read(operational, offset);
        if (force_reset || !(status & port_enabled)) {
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
        if (force_reset) {
            wait_usb_recovery();
            status = read(operational, offset);
        }
        speed = (status >> 10) & 15;
        return (status & (port_enabled | port_connected)) == (port_enabled | port_connected) &&
               speed >= 1 && speed <= 5;
    }

    bool probe_device(unsigned port, ProbeMode mode, bool retry = false) {
        unsigned speed, slot = 0;
        if (!enable_port(port, speed, retry) || (retry && speed != 1) ||
            !command(enable_slot, 0, 0, &slot) || !slot || slot > slots || devices[slot])
            return false;
        const uint64_t input = Dma::allocate(device_pages, Dma::pci);
        if (!input)
            return false;
        devices[slot] = input;
        auto contexts = static_cast<uint32_t*>(physical(input));
        auto slot_context = contexts + context_words;
        auto endpoint = slot_context + context_words;
        const uint64_t transfer = input + 2 * page_size;
        const unsigned initial_packet = speed >= 4 ? 512 : (speed == 3 || retry) ? 64 : 8;
        contexts[1] = 3; // Add the slot and default control endpoint.
        slot_context[0] = (1u << 27) | (speed << 20);
        slot_context[1] = port << 16;
        endpoint[1] = (initial_packet << 16) | (4 << 3) | (3 << 1);
        endpoint[2] = uint32_t(transfer) | 1;
        endpoint[3] = transfer >> 32;
        endpoint[4] = 8;
        static_cast<uint64_t*>(physical(dma))[slot] = input + page_size;
        if (!command(address_device, input, slot))
            return false;
        // Allow the device to settle after SET_ADDRESS before using endpoint zero.
        wait_usb_recovery();
        constexpr unsigned stall = 6;
        unsigned completion_code = 0;
        constexpr uint64_t get_device_descriptor = (1ull << 24) | 0x0680;
        if (!control_transfer(slot, get_device_descriptor, retry ? 64 : 8, &completion_code)) {
            if (retry || speed != 1 || completion_code != stall || !command(disable_slot, 0, slot))
                return false;
            static_cast<uint64_t*>(physical(dma))[slot] = 0;
            devices[slot] = 0;
            control_next[slot] = 0;
            page_free(input, device_pages);
            log("xhci-enumeration: retry full-speed device on port=%u\n", uint64_t(port));
            return probe_device(port, mode, true);
        }
        auto descriptor = static_cast<const uint8_t*>(physical(input + 3 * page_size));
        if (descriptor[0] != descriptor_size || descriptor[1] != 1)
            return false;
        const unsigned packet = speed >= 4 && descriptor[7] == 9 ? 512 : descriptor[7];
        if (packet != initial_packet) {
            if (speed != 1 || (packet != 8 && packet != 16 && packet != 32 && packet != 64))
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
        if ((!retry && !read_descriptor(slot, 1, descriptor_size)) ||
            descriptor[0] != descriptor_size || descriptor[1] != 1 || !descriptor[17])
            return false;
        log("xhci-device: port=%u speed=%u vendor=%x product=%x configurations=%u\n",
            uint64_t(port), uint64_t(speed), uint64_t(descriptor[8] | (descriptor[9] << 8)),
            uint64_t(descriptor[10] | (descriptor[11] << 8)), uint64_t(descriptor[17]));
        return probe_configuration(slot, port, speed, mode, retry);
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
    if (controller.dma && stopped)
        controller.release_dma();
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
        if (stopped)
            controller.release_dma();
        success &= stopped;
    }
    active_count = 0;
    return success;
}
} // namespace ax
