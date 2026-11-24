// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/designware_i2c.hpp
 * @brief   Transfers bytes through a quiescent DesignWare I²C controller.
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
#pragma once
#include "drivers/platform/poll.hpp"

namespace ax::DesignWareI2c {
constexpr unsigned control = 0x00, target = 0x04, data = 0x10;
constexpr unsigned standard_high = 0x14, fast_high = 0x1c, interrupt_mask = 0x30;
constexpr unsigned raw_interrupts = 0x34, clear_interrupts = 0x40, enable = 0x6c, status = 0x70;
constexpr unsigned tx_level = 0x74, rx_level = 0x78, sda_hold = 0x7c, abort_source = 0x80;
constexpr unsigned dma = 0x88, enable_status = 0x9c, version = 0xf8;
constexpr unsigned read_byte = 1 << 8, stop = 1 << 9, restart = 1 << 10;
constexpr unsigned active = 1, tx_room = 1 << 1, rx_data = 1 << 3;
constexpr unsigned tx_abort = 1 << 6, stop_seen = 1 << 9;
constexpr unsigned fifo_error = (1 << 0) | (1 << 1) | (1 << 3);
constexpr unsigned hid_descriptor_bytes = 30, max_report_descriptor_bytes = 4096;

enum class Result : uint8_t { ok, invalid, busy, timeout, bus_error, restore_failed };

struct HidDescriptor {
    uint16_t report_bytes, report_register, input_register, input_bytes;
    uint16_t command_register, data_register;
    uint16_t vendor, product, revision;
};

inline bool decode_hid(const uint8_t (&raw)[hid_descriptor_bytes], HidDescriptor& out) {
    auto word = [&](unsigned offset) { return uint16_t(raw[offset] | raw[offset + 1] << 8); };
    if (word(0) != hid_descriptor_bytes || word(2) != 0x0100 || !word(4) || word(10) < 2)
        return false;
    out = {word(4), word(6), word(8), word(10), word(16), word(18), word(20), word(22), word(24)};
    return true;
}

inline unsigned clock_count(uint32_t input_hz, unsigned period_ns) {
    return (uint64_t(input_hz) * period_ns + 999999999) / 1000000000;
}

// The caller owns the bus, powers the controller and supplies its input clock.
// Byte mode leaves at most one read request in flight and needs no FIFO-depth assumptions.
template <class Registers>
Result transfer(Registers& io, uint32_t input_hz, uint32_t max_speed, uint16_t address,
                const uint8_t* output, unsigned output_size, uint8_t* input, unsigned input_size,
                uint32_t& abort, unsigned timeout_override = 0) {
    abort = 0;
    if ((!output_size && !input_size) || (output_size && !output) || (input_size && !input) ||
        output_size > max_report_descriptor_bytes || input_size > max_report_descriptor_bytes ||
        address < 0x08 || address > 0x77 || input_hz < 10000000 || input_hz > 1000000000 ||
        max_speed < 100000)
        return Result::invalid;
    if (io.read(enable) || (io.read(enable_status) & 1) || (io.read(status) & active) ||
        io.read(tx_level) || io.read(rx_level))
        return Result::busy;

    const bool fast = max_speed >= 400000;
    const unsigned high_register = fast ? fast_high : standard_high;
    const bool has_hold = io.read(version) >= 0x3131312a;
    const uint32_t old_control = io.read(control), old_target = io.read(target);
    const uint32_t old_high = io.read(high_register), old_low = io.read(high_register + 4);
    const uint32_t old_mask = io.read(interrupt_mask), old_dma = io.read(dma);
    const uint32_t old_hold = has_hold ? io.read(sda_hold) : 0;
    io.write(interrupt_mask, 0);
    io.write(dma, 0);
    io.read(clear_interrupts);
    io.write(control, 1 | (fast ? 4 : 2) | (1 << 5) | (1 << 6));
    io.write(target, address);
    io.write(high_register, clock_count(input_hz, fast ? 900 : 4700) - 3);
    io.write(high_register + 4, clock_count(input_hz, fast ? 1600 : 5300) - 1);
    if (has_hold)
        io.write(sda_hold, (old_hold & ~0xffffu) | clock_count(input_hz, 230));
    io.write(enable, 1);

    const unsigned bus_hz = fast ? 400000 : 100000;
    // Each byte takes nine SCL clocks. Allow two wire times and margin for clock stretching.
    const unsigned timeout =
        timeout_override ? timeout_override
                         : 20 + ((input_size + output_size + 2) * 18000 + bus_hz - 1) / bus_hz;
    unsigned sent = 0, requested = 0, received = 0;
    Result result = Result::timeout;
    if (DevicePoll::wait([&] { return io.read(enable_status) & 1; }, 5)) {
        const bool finished = DevicePoll::wait(
            [&] {
                const unsigned interrupts = io.read(raw_interrupts);
                if (interrupts & (tx_abort | fifo_error)) {
                    if (interrupts & tx_abort)
                        abort = io.read(abort_source);
                    result = Result::bus_error;
                    return true;
                }
                const unsigned port = io.read(status);
                if (port & rx_data) {
                    if (received >= requested) {
                        result = Result::bus_error;
                        return true;
                    }
                    input[received++] = io.read(data);
                }
                if (sent == output_size && received == input_size && (interrupts & stop_seen) &&
                    !(port & active)) {
                    result = Result::ok;
                    return true;
                }
                if (port & tx_room) {
                    if (sent < output_size) {
                        unsigned command = output[sent++];
                        if (sent == output_size && !input_size)
                            command |= stop;
                        io.write(data, command);
                    } else if (requested == received && requested < input_size) {
                        unsigned command = read_byte;
                        if (requested == 0 && output_size)
                            command |= restart;
                        if (++requested == input_size)
                            command |= stop;
                        io.write(data, command);
                    }
                }
                return false;
            },
            timeout);
        if (!finished)
            result = Result::timeout;
    }

    if (result != Result::ok && (io.read(status) & active) && (io.read(enable_status) & 1)) {
        io.write(enable, 3); // Request abort while the controller is enabled.
        DevicePoll::wait([&] { return !(io.read(enable) & 2); }, 5);
    }
    io.write(enable, 0);
    if (!DevicePoll::wait([&] { return !(io.read(enable_status) & 1); }, 5) ||
        (io.read(status) & active) || io.read(tx_level) || io.read(rx_level))
        return Result::restore_failed;
    io.read(clear_interrupts);
    io.write(control, old_control);
    io.write(target, old_target);
    io.write(high_register, old_high);
    io.write(high_register + 4, old_low);
    if (has_hold)
        io.write(sda_hold, old_hold);
    io.write(interrupt_mask, old_mask);
    io.write(dma, old_dma);
    if (io.read(control) != old_control || io.read(target) != old_target ||
        io.read(high_register) != old_high || io.read(high_register + 4) != old_low ||
        (has_hold && io.read(sda_hold) != old_hold) || io.read(interrupt_mask) != old_mask ||
        io.read(dma) != old_dma)
        return Result::restore_failed;
    return result;
}

template <class Registers>
Result read_register(Registers& io, uint32_t input_hz, uint32_t max_speed, uint16_t address,
                     uint16_t device_register, uint8_t* bytes, unsigned length, uint32_t& abort) {
    if (!length) {
        abort = 0;
        return Result::invalid;
    }
    const uint8_t output[]{uint8_t(device_register), uint8_t(device_register >> 8)};
    return transfer(io, input_hz, max_speed, address, output, sizeof(output), bytes, length, abort);
}

template <class Registers>
Result read_hid(Registers& io, uint32_t input_hz, uint32_t max_speed, uint16_t address,
                uint16_t descriptor_register, HidDescriptor& out, uint32_t& abort) {
    uint8_t raw[hid_descriptor_bytes]{};
    const auto result = read_register(io, input_hz, max_speed, address, descriptor_register, raw,
                                      sizeof(raw), abort);
    return result == Result::ok && !decode_hid(raw, out) ? Result::invalid : result;
}
} // namespace ax::DesignWareI2c
