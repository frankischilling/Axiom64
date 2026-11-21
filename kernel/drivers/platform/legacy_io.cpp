// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/legacy_io.cpp
 * @brief   Fixed ISA UART and parallel printer drivers.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Probes COM1 and LPT1, bounds polling, and sends bytes through legacy port I/O.
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
#include "drivers/platform/legacy_io.hpp"
#include "core/base.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
constexpr uint16_t com1 = 0x3f8;
constexpr uint16_t lpt1 = 0x378;
constexpr unsigned uart_wait = 100000;
constexpr unsigned printer_wait = 10000;

constexpr uint8_t data_ready = 0x01;
constexpr uint8_t transmit_empty = 0x20;
constexpr uint8_t printer_strobe = 0x01;
constexpr uint8_t printer_autofeed = 0x02;
constexpr uint8_t printer_idle = 0x0c;        // Selected, with INIT deasserted.
constexpr uint8_t printer_status_mask = 0xb8; // Not busy, no paper-out, selected, no error.
constexpr uint8_t printer_ready = 0x98;

bool uart_present;

bool serial_byte(uint8_t value) {
    for (unsigned attempt = 0; attempt < uart_wait; ++attempt) {
        const uint8_t status = in8(com1 + 5);
        if (status == 0xff)
            return false;
        if (status & transmit_empty) {
            out8(com1, value);
            return true;
        }
        asm volatile("pause");
    }
    return false;
}

bool wait_for_printer() {
    for (unsigned attempt = 0; attempt < printer_wait; ++attempt) {
        const uint8_t status = in8(lpt1 + 1);
        if ((status & printer_status_mask) == printer_ready)
            return true;
        // BUSY is transient. Disconnection, paper-out, and errors fail immediately.
        if ((status & (printer_status_mask & ~0x80)) != (printer_ready & ~0x80))
            return false;
        asm volatile("pause");
    }
    return false;
}
} // namespace

void serial_init() {
    uart_present = false;
    if (in8(com1 + 5) == 0xff)
        return;
    const uint8_t saved = in8(com1 + 7);
    out8(com1 + 7, 0x5a);
    const bool first = in8(com1 + 7) == 0x5a;
    out8(com1 + 7, 0xa5);
    const bool second = in8(com1 + 7) == 0xa5;
    out8(com1 + 7, saved);
    if (!first || !second)
        return;

    out8(com1 + 3, 3); // Clear DLAB before disabling UART interrupts.
    out8(com1 + 1, 0);
    out8(com1 + 3, 0x80);
    out8(com1, 1); // 115200 baud.
    out8(com1 + 1, 0);
    out8(com1 + 3, 3); // Eight data bits, no parity, one stop bit.
    out8(com1 + 2, 0xc7);
    out8(com1 + 4, 0x0b);
    uart_present = true;
}

bool serial_present() {
    return uart_present;
}

bool serial_put(char value) {
    return uart_present && (value != '\n' || serial_byte('\r')) && serial_byte(value);
}

int serial_read() {
    if (!uart_present)
        return -1;
    const uint8_t status = in8(com1 + 5);
    return status != 0xff && (status & data_ready) ? in8(com1) : -1;
}

bool parallel_init() {
    if (in8(lpt1 + 1) == 0xff || !clock_delay_us(1))
        return false;
    const uint8_t saved = in8(lpt1 + 2);
    const uint8_t trial = saved ^ printer_autofeed;
    out8(lpt1 + 2, trial);
    const bool present = (in8(lpt1 + 2) & 0x0f) == (trial & 0x0f);
    out8(lpt1 + 2, saved);
    if (present)
        out8(lpt1 + 2, printer_idle);
    return present;
}

int64_t parallel_write(const void* data, size_t length) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < length && wait_for_printer()) {
        out8(lpt1, bytes[sent]);
        if (!clock_delay_us(1))
            break;
        out8(lpt1 + 2, printer_idle | printer_strobe);
        const bool timed = clock_delay_us(1);
        out8(lpt1 + 2, printer_idle);
        ++sent;
        if (!timed || !clock_delay_us(1))
            break;
    }
    return sent || !length ? int64_t(sent) : -5;
}
} // namespace ax
