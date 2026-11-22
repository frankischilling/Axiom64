// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/platform/designware_i2c.cpp
 * @brief   Exercises the DesignWare HID read against a register model.
 * @author  frankischilling
 * @date    2026-11-22
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
#include "drivers/input/hid_touchpad.hpp"
#include "drivers/platform/designware_i2c.hpp"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef AXIOM64_GUEST_TEST
#include <sys/reboot.h>
#endif

namespace ax {
uint64_t ticks;

void clock_refresh(bool) {
    ++ticks;
}
} // namespace ax

namespace {
using namespace ax::DesignWareI2c;

enum class Mode { normal, nack, silent, malformed, refuse_disable };

struct Controller {
    Mode mode{};
    uint32_t registers[64]{};
    uint32_t commands[max_report_descriptor_bytes + 2]{};
    const uint8_t* reply = nullptr;
    unsigned reply_length = hid_descriptor_bytes;
    unsigned count = 0, replied = 0, writes = 0;
    uint32_t events = 0;
    bool queued = false, busy = false, aborted = false;

    uint32_t read(unsigned offset) {
        if (offset == status)
            return tx_room | (busy ? active : 0) | (queued ? rx_data : 0);
        if (offset == rx_level)
            return queued;
        if (offset == raw_interrupts)
            return events;
        if (offset == abort_source)
            return 1;
        if (offset == clear_interrupts) {
            events = 0;
            return 0;
        }
        if (offset == data) {
            assert(queued && replied < reply_length);
            queued = false;
            if (reply)
                return reply[replied++];
            const uint8_t descriptor[hid_descriptor_bytes]{
                30, 0, 0, 1, 52, 0,    2,    0,    3,    0,    64, 0, 4, 0, 0,
                0,  5, 0, 6, 0,  0xf3, 0x04, 0xa6, 0x30, 0x21, 0,  0, 0, 0, 0};
            const unsigned index = replied++;
            return mode == Mode::malformed && index == 0 ? 29 : descriptor[index];
        }
        return registers[offset / 4];
    }

    void write(unsigned offset, uint32_t value) {
        ++writes;
        if (offset == enable) {
            if (value == 3) {
                assert(registers[enable_status / 4] == 1);
                aborted = true;
                busy = queued = false;
                events |= tx_abort;
                value = 1;
            }
            if (mode == Mode::refuse_disable && !value)
                return;
            registers[enable_status / 4] = value & 1;
        }
        if (offset != data) {
            registers[offset / 4] = value;
            return;
        }
        assert(registers[enable_status / 4] == 1 && count < sizeof(commands) / sizeof(*commands));
        assert(registers[interrupt_mask / 4] == 0 && registers[dma / 4] == 0);
        assert(registers[target / 4] == 0x15);
        commands[count++] = value;
        busy = true;
        if (mode == Mode::nack) {
            events |= tx_abort;
            busy = false;
        } else if ((value & read_byte) && mode != Mode::silent) {
            assert(!queued);
            queued = true;
            if (value & stop) {
                events |= stop_seen;
                busy = false;
            }
        }
    }
};

Controller fresh(Mode mode) {
    Controller controller{};
    controller.mode = mode;
    controller.registers[control / 4] = 0x43;
    controller.registers[target / 4] = 0x20;
    controller.registers[standard_high / 4] = 17;
    controller.registers[(standard_high + 4) / 4] = 19;
    controller.registers[fast_high / 4] = 23;
    controller.registers[(fast_high + 4) / 4] = 29;
    controller.registers[interrupt_mask / 4] = 0x10;
    controller.registers[dma / 4] = 1;
    controller.registers[sda_hold / 4] = 0x33;
    controller.registers[version / 4] = 0x3131312a;
    return controller;
}

void check_transfer() {
    uint32_t abort = 0;
    HidDescriptor descriptor{};
    auto run = [&](Controller& controller, uint32_t speed = 400000) {
        return read_hid(controller, 216000000, speed, 0x15, 0x0123, descriptor, abort);
    };
    const unsigned speeds[]{100000, 400000};
    for (unsigned speed : speeds) {
        auto controller = fresh(Mode::normal);
        assert(run(controller, speed) == Result::ok && !abort);
        assert(controller.count == hid_descriptor_bytes + 2 &&
               controller.replied == hid_descriptor_bytes);
        assert(controller.commands[0] == 0x23 && controller.commands[1] == 0x01);
        assert(controller.commands[2] == (read_byte | restart));
        for (unsigned i = 3; i < hid_descriptor_bytes + 1; ++i)
            assert(controller.commands[i] == read_byte);
        assert(controller.commands[hid_descriptor_bytes + 1] == (read_byte | stop));
        assert(descriptor.vendor == 0x04f3 && descriptor.product == 0x30a6 &&
               descriptor.input_bytes == 64 && descriptor.report_bytes == 52);
        const auto before = fresh(Mode::normal);
        for (unsigned i = 0; i < sizeof(controller.registers) / sizeof(*controller.registers); ++i)
            assert(controller.registers[i] == before.registers[i]);
    }
    auto nack = fresh(Mode::nack);
    assert(run(nack) == Result::bus_error && abort == 1 && !nack.read(enable));
    auto silent = fresh(Mode::silent);
    assert(run(silent) == Result::timeout && silent.aborted && !silent.read(enable));
    auto malformed = fresh(Mode::malformed);
    assert(run(malformed) == Result::invalid && !malformed.read(enable));
    auto stuck = fresh(Mode::refuse_disable);
    assert(run(stuck) == Result::restore_failed && stuck.read(enable));
    auto active_bus = fresh(Mode::normal);
    active_bus.busy = true;
    assert(run(active_bus) == Result::busy && !active_bus.writes);
    assert(run(active_bus, 50000) == Result::invalid && !active_bus.writes);
    puts("DESIGNWARE_HID_PASS restart stop standard fast nack timeout rollback");
}

void check_large_register_read() {
    uint8_t reply[max_report_descriptor_bytes], readback[max_report_descriptor_bytes]{};
    for (unsigned i = 0; i < sizeof(reply); ++i)
        reply[i] = uint8_t(i ^ (i >> 8));
    auto controller = fresh(Mode::normal);
    controller.reply = reply;
    controller.reply_length = sizeof(reply);
    uint32_t abort = 0;
    assert(read_register(controller, 216000000, 100000, 0x15, 0xfe21, readback, sizeof(readback),
                         abort) == Result::ok);
    assert(!abort && controller.count == sizeof(readback) + 2 &&
           controller.replied == sizeof(readback) && !memcmp(reply, readback, sizeof(reply)));
    assert(controller.commands[0] == 0x21 && controller.commands[1] == 0xfe);
    assert(controller.commands[2] == (read_byte | restart));
    assert(controller.commands[sizeof(readback) + 1] == (read_byte | stop));
    for (unsigned i = 3; i < sizeof(readback) + 1; ++i)
        assert(controller.commands[i] == read_byte);
    const auto before = fresh(Mode::normal);
    assert(!memcmp(controller.registers, before.registers, sizeof(before.registers)));

    const auto writes = controller.writes;
    assert(read_register(controller, 216000000, 400000, 0x15, 2, readback, sizeof(readback) + 1,
                         abort) == Result::invalid &&
           controller.writes == writes);
    assert(read_register(controller, 216000000, 400000, 0x15, 2, nullptr, 1, abort) ==
               Result::invalid &&
           controller.writes == writes);
    puts("DESIGNWARE_REPORT_READ_PASS bytes=4096 stop_bounds");
}

#define FINGER_ITEMS                                                                               \
    0x09, 0x22, 0xa1, 0x02, /* Finger logical collection */                                        \
        0x15, 0, 0x25, 1, 0x09, 0x42, 0x09, 0x47, 0x75, 1, 0x95, 2, 0x81, 0x02, /* Flags */        \
        0x95, 6, 0x81, 1,                                                       /* Padding */      \
        0x09, 0x51, 0x25, 0x7f, 0x75, 8, 0x95, 1, 0x81, 0x02,                   /* Contact ID */   \
        0xa4, 0x05, 1, 0x15, 0xe0, 0x26, 0xff, 3, 0x19, 0x30, 0x29, 0x31, 0x75, 16, 0x95, 2, 0x81, \
        2, 0xb4, 0xc0 /* Signed X and Y. Pop returns to the digitizer page. */

void check_touchpad_layout() {
    using namespace ax::HidTouchpad;
    const uint8_t descriptor[]{
        0x05,
        0x0d,
        0x09,
        5,
        0xa1,
        1,
        0x85,
        7, // Touchpad application and report ID.
        FINGER_ITEMS,
        FINGER_ITEMS,
        0x09,
        0x54,
        0x15,
        0,
        0x25,
        10,
        0x75,
        8,
        0x95,
        1,
        0x81,
        2, // Contact count.
        0x05,
        9,
        0x09,
        1,
        0x25,
        1,
        0x75,
        1,
        0x81,
        2, // Click switch.
        0x75,
        7,
        0x81,
        1,
        0xc0,
        0x05,
        1,
        0x09,
        2,
        0xa1,
        1,
        0x85,
        8,
        0x09,
        0x30,
        0x75,
        8,
        0x81,
        6,
        0xc0, // Relative mouse.
    };
    uint8_t raw[sizeof(descriptor)]{};
    auto controller = fresh(Mode::normal);
    controller.reply = descriptor;
    controller.reply_length = sizeof(descriptor);
    uint32_t abort = 0;
    assert(read_register(controller, 216000000, 400000, 0x15, 0x0102, raw, sizeof(raw), abort) ==
               Result::ok &&
           !abort);
    assert(controller.commands[0] == 2 && controller.commands[1] == 1);
    Layouts layouts{};
    assert(parse(raw, sizeof(raw), 17, layouts));
    assert(layouts.numbered && layouts.count == 1 && layouts.reports[0].id == 7 &&
           layouts.reports[0].finger_count == 2 && layouts.reports[0].bits == 112);
    uint8_t packet[]{17, 0, 7, 3, 4, 0xe8, 0xff, 200, 0, 1, 6, 0xee, 2, 0xff, 3, 2, 1, 0, 0};
    Frame frame{};
    assert(decode(layouts, packet, sizeof(packet), frame) == Packet::input);
    assert(frame.slots == 2 && frame.button && frame.has_contact_count && frame.contact_count == 2);
    assert(frame.fingers[0].touching && frame.fingers[0].confident && frame.fingers[0].id == 4 &&
           frame.fingers[0].x == -24 && frame.fingers[0].y == 200);
    assert(frame.fingers[1].touching && !frame.fingers[1].confident && frame.fingers[1].id == 6 &&
           frame.fingers[1].x == 750 && frame.fingers[1].y == 1023);
    packet[9] = 0;
    packet[16] = 0;
    packet[13] = packet[14] = 0xff;
    assert(decode(layouts, packet, sizeof(packet), frame) == Packet::input && !frame.button &&
           !frame.fingers[1].touching);
    packet[9] = 1;
    packet[14] = 0x7f;
    assert(decode(layouts, packet, sizeof(packet), frame) == Packet::invalid);
    packet[0] = 16;
    assert(decode(layouts, packet, sizeof(packet), frame) == Packet::invalid);
    packet[0] = 17;
    assert(decode(layouts, packet, 16, frame) == Packet::invalid);
    packet[2] = 8;
    assert(decode(layouts, packet, sizeof(packet), frame) == Packet::unknown);
    packet[0] = 0;
    assert(decode(layouts, packet, sizeof(packet), frame) == Packet::reset);
    assert(!parse(raw, sizeof(raw), 16, layouts) && !layouts.count);
    assert(!parse(raw, sizeof(raw) - 1, 17, layouts) && !layouts.count);
    const uint8_t bad_long[]{0xfe, 5, 0x44, 7};
    assert(!parse(bad_long, sizeof(bad_long), 17, layouts) && !layouts.count);

    // The parser must also accept descriptors and packets without a report ID.
    const uint8_t single[]{0x05, 0x0d, 0x09, 5, 0xa1, 1, FINGER_ITEMS, 0xc0};
    assert(parse(single, sizeof(single), 8, layouts) && !layouts.numbered);
    const uint8_t report[]{8, 0, 3, 1, 0, 0, 1, 0};
    assert(decode(layouts, report, sizeof(report), frame) == Packet::input && frame.slots == 1 &&
           !frame.has_contact_count && frame.fingers[0].y == 1);
    layouts.reports[0].fingers[0].tip.offset = 100;
    assert(decode(layouts, report, sizeof(report), frame) == Packet::invalid);
    puts("HID_TOUCHPAD_PASS two_slots signed_axes report_ids clicks truncated_frames");
}

#undef FINGER_ITEMS
} // namespace

int main() {
    check_transfer();
    check_large_register_read();
    check_touchpad_layout();
    fflush(stdout);
#ifdef AXIOM64_GUEST_TEST
    reboot(RB_POWER_OFF);
#endif
}
