// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/platform/isa_pnp.cpp
 * @brief   Discovers firmware-configured ISA Plug and Play devices.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Isolates ISA cards, validates their resource streams, and reads active port assignments.
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
#include "drivers/platform/isa_pnp.hpp"
#include <stddef.h>

namespace ax::IsaPnp {
namespace {
constexpr uint16_t address_port = 0x279, write_port = 0xa79;
constexpr uint16_t read_ports[]{0x213, 0x243, 0x263};
constexpr uint8_t set_read_port = 0x00, serial_isolation = 0x01, config_control = 0x02, wake = 0x03,
                  resource_data = 0x04, status = 0x05, card_select = 0x06, logical_device = 0x07,
                  activate = 0x30, first_io_base = 0x60;
constexpr uint8_t wait_for_key = 2, reset_card_numbers = 4;
constexpr unsigned max_cards = 16, max_devices = 32, max_alternatives = 8;
constexpr unsigned max_resource_bytes = 2048, resource_wait_us = 200000;

uint8_t shift_lfsr(uint8_t state, bool input = false) {
    return (state >> 1) | (((state ^ (state >> 1) ^ input) & 1) << 7);
}

struct Transport {
    const Bus& bus;
    uint16_t read_port;

    void select(uint8_t reg) const {
        bus.write(bus.context, address_port, reg);
    }

    void write(uint8_t reg, uint8_t value) const {
        select(reg);
        bus.write(bus.context, write_port, value);
    }

    uint8_t read(uint8_t reg) const {
        select(reg);
        return bus.read(bus.context, read_port);
    }

    bool delay(unsigned us) const {
        return bus.delay(bus.context, us);
    }

    void key() const {
        select(0);
        select(0);
        for (uint8_t state = 0x6a, i = 0; i < 32; ++i, state = shift_lfsr(state))
            select(state);
    }

    bool begin() const {
        write(config_control, wait_for_key);
        key();
        write(config_control, reset_card_numbers);
        if (!delay(2000))
            return false;
        write(config_control, wait_for_key);
        key();
        return true;
    }

    bool isolate(uint8_t (&id)[9]) const {
        write(wake, 0);
        write(set_read_port, uint8_t(read_port >> 2));
        if (!delay(1000))
            return false;
        select(serial_isolation);
        if (!delay(1000))
            return false;

        uint8_t checksum = 0x6a;
        bool response = false;
        for (unsigned bit = 0; bit < 72; ++bit) {
            const auto first = bus.read(bus.context, read_port);
            if (!delay(250))
                return false;
            const auto second = bus.read(bus.context, read_port);
            if (!delay(250))
                return false;
            const bool one = first == 0x55 && second == 0xaa;
            id[bit / 8] |= uint8_t(one) << (bit % 8);
            if (bit < 64) {
                response |= one;
                checksum = shift_lfsr(checksum, one);
            }
        }
        return response && id[8] == checksum;
    }

    bool read_resources(uint8_t (&bytes)[max_resource_bytes], size_t& length) const {
        unsigned remaining_wait = resource_wait_us;
        auto next_byte = [&](uint8_t& byte) {
            unsigned waits = 0;
            while (!(read(status) & 1)) {
                if (++waits >= 20 || !remaining_wait || !delay(100))
                    return false;
                remaining_wait -= 100;
            }
            if (length == max_resource_bytes)
                return false;
            byte = read(resource_data);
            bytes[length++] = byte;
            return true;
        };
        while (length < max_resource_bytes) {
            uint8_t tag;
            if (!next_byte(tag))
                return false;
            unsigned size = tag & 7;
            if (tag & 0x80) {
                uint8_t low, high;
                if (!next_byte(low) || !next_byte(high))
                    return false;
                size = unsigned(low) | (unsigned(high) << 8);
            }
            if (size > max_resource_bytes - length)
                return false;
            for (unsigned i = 0; i < size; ++i) {
                uint8_t value;
                if (!next_byte(value))
                    return false;
            }
            if ((tag & 0xf8) == 0x78)
                return tag == 0x79;
        }
        return false;
    }
};

enum class Kind { other, uart, printer };

Kind classify(const uint8_t* id) {
    // PNP0500 and PNP0501 describe standard serial ports. PNP0400 is SPP.
    if (id[0] != 0x41 || id[1] != 0xd0)
        return Kind::other;
    if (id[2] == 5 && id[3] <= 1)
        return Kind::uart;
    return id[2] == 4 && !id[3] ? Kind::printer : Kind::other;
}

uint16_t little_word(const uint8_t* bytes) {
    return uint16_t(bytes[0]) | (uint16_t(bytes[1]) << 8);
}

struct Range {
    uint16_t first, last;
    uint8_t align, length;

    bool contains(uint16_t base, unsigned required) const {
        return length >= required && base >= first && base <= last &&
               unsigned(base) + length <= 0x10000 &&
               (align ? (base - first) % align == 0 : base == first);
    }
};

struct LogicalDevice {
    Kind kind;
    Range common;
    Range alternatives[max_alternatives];
    unsigned alternative_count;
    bool common_first;
    bool unsupported;
};

bool parse(const uint8_t* data, size_t length, LogicalDevice (&devices)[max_devices],
           unsigned& count) {
    uint8_t sum = 0;
    for (size_t i = 0; i < length; ++i)
        sum += data[i];
    LogicalDevice* device = nullptr;
    bool dependent = false;
    size_t position = 0;
    while (position < length) {
        const uint8_t tag = data[position++];
        size_t size = tag & 7;
        if (tag & 0x80) {
            if (length - position < 2)
                return false;
            size = little_word(data + position);
            position += 2;
        }
        if (size > length - position)
            return false;
        const auto* payload = data + position;
        position += size;
        if (tag & 0x80)
            continue;
        const unsigned type = tag >> 3;
        if (type == 0x0f)
            return size == 1 && position == length && !dependent && (!payload[0] || !sum);
        if (type == 2) {
            if (dependent || count == max_devices || (size != 5 && size != 6))
                return false;
            device = &devices[count++];
            device->kind = classify(payload);
            continue;
        }
        if (!device)
            continue;
        if (type == 3) {
            if (size != 4)
                return false;
            if (device->kind == Kind::other)
                device->kind = classify(payload);
        } else if (type == 6) {
            if (size > 1)
                return false;
            if ((!dependent && device->alternative_count) ||
                device->alternative_count == max_alternatives)
                device->unsupported = true;
            else
                ++device->alternative_count;
            dependent = true;
        } else if (type == 7) {
            if (!dependent || size)
                return false;
            dependent = false;
        } else if (type == 8 || type == 9) {
            if (size != (type == 8 ? 7u : 3u))
                return false;
            if ((type == 8 && (payload[0] & 0xfe)) || (type == 9 && (payload[1] & 0xfc)))
                return false;
            const Range range =
                type == 8 ? Range{little_word(payload + 1), little_word(payload + 3), payload[5],
                                  payload[6]}
                          : Range{little_word(payload), little_word(payload), 0, payload[2]};
            if (!range.length || range.first > range.last)
                return false;
            if (device->unsupported)
                continue;
            if (dependent) {
                auto& first = device->alternatives[device->alternative_count - 1];
                if (!first.length)
                    first = range;
            } else if (!device->common.length) {
                device->common = range;
                device->common_first = !device->alternative_count;
            }
        }
    }
    return false;
}

bool permitted(const LogicalDevice& device, uint16_t base) {
    if (device.unsupported)
        return false;
    const unsigned width = device.kind == Kind::uart ? 8 : 3;
    if (device.kind == Kind::uart && base != 0x3f8 && base != 0x2f8 && base != 0x3e8 &&
        base != 0x2e8)
        return false;
    if (device.kind == Kind::printer && base != 0x378 && base != 0x278 && base != 0x3bc)
        return false;
    if (device.common_first || !device.alternative_count)
        return device.common.contains(base, width);
    for (unsigned i = 0; i < device.alternative_count; ++i) {
        const auto& range = device.alternatives[i];
        if ((range.length ? range : device.common).contains(base, width))
            return true;
    }
    return false;
}

struct Candidates {
    uint16_t base = 0;
    bool ambiguous = false;

    void add(uint16_t port) {
        if (base)
            ambiguous = true;
        else
            base = port;
    }
};

bool read_card(const Transport& transport, Candidates& uart, Candidates& printer) {
    uint8_t resource[max_resource_bytes];
    size_t length = 0;
    LogicalDevice devices[max_devices]{};
    unsigned count = 0;
    if (!transport.read_resources(resource, length) || !parse(resource, length, devices, count))
        return false;

    for (unsigned i = 0; i < count; ++i) {
        const auto& device = devices[i];
        if (device.kind == Kind::other)
            continue;
        transport.write(logical_device, i);
        if (transport.read(logical_device) != i || transport.read(activate) != 1)
            continue;
        const auto high = transport.read(first_io_base);
        const auto low = transport.read(first_io_base + 1);
        const auto base = uint16_t((uint16_t(high) << 8) | low);
        if (permitted(device, base))
            (device.kind == Kind::uart ? uart : printer).add(base);
    }
    return true;
}
} // namespace

Ports discover(const Bus& bus) {
    Ports result;
    Candidates uart, printer;
    for (auto port : read_ports) {
        const Transport transport{bus, port};
        if (!transport.begin()) {
            transport.write(config_control, wait_for_key);
            return result;
        }
        uint8_t ids[max_cards][9]{};
        for (unsigned i = 0; i < max_cards && transport.isolate(ids[i]); ++i) {
            bool duplicate = false;
            for (unsigned previous = 0; previous < i; ++previous) {
                bool same = true;
                for (unsigned j = 0; j < 8; ++j)
                    same &= ids[i][j] == ids[previous][j];
                duplicate |= same;
            }
            if (duplicate)
                break;
            const auto number = uint8_t(i + 1);
            transport.write(card_select, number);
            if (!transport.delay(250) || transport.read(card_select) != number)
                break;
            ++result.cards;
            if (!read_card(transport, uart, printer))
                ++result.rejected;
        }
        transport.write(config_control, wait_for_key);
        if (result.cards == max_cards)
            return result; // An unexamined card might also claim an I/O range.
        if (result.cards)
            break;
    }
    if (!uart.ambiguous)
        result.uart = uart.base;
    if (!printer.ambiguous)
        result.printer = printer.base;
    return result;
}
} // namespace ax::IsaPnp
