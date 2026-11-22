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
#include "drivers/platform/designware_i2c.hpp"
#include <assert.h>
#include <stdio.h>
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
    uint32_t commands[hid_descriptor_bytes + 2]{};
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
            assert(queued && replied < hid_descriptor_bytes);
            queued = false;
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
} // namespace

int main() {
    check_transfer();
    fflush(stdout);
#ifdef AXIOM64_GUEST_TEST
    reboot(RB_POWER_OFF);
#endif
}
