// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/ata.cpp
 * @brief   Polled legacy ATA disk driver.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Binds PCI IDE compatibility channels, identifies disks, and transfers
 * 512-byte sectors through their taskfile registers.
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
#include "drivers/block/ata.hpp"
#include "core/time.hpp"
#include "drivers/platform/pci.hpp"

namespace ax {
namespace {
constexpr uint8_t busy = 0x80;
constexpr uint8_t ready = 0x40;
constexpr uint8_t fault = 0x20;
constexpr uint8_t drq = 0x08;
constexpr uint8_t error = 0x01;
constexpr uint8_t disable_irq = 0x02;
constexpr uint64_t lba28_limit = 1ull << 28;
constexpr uint64_t lba48_limit = 1ull << 48;

struct Channel {
    uint16_t base, control;
    bool enabled = false, failed = false;
};

struct Drive {
    BlockInfo info;
    uint8_t flush_command;
};

Channel channels[]{{0x1f0, 0x3f6}, {0x170, 0x376}};
Drive drives[ata_device_slots]{};
bool duplicate_controller;

uint8_t status(const Channel& channel) {
    return in8(channel.control);
}

void settle(const Channel& channel) {
    // Read alternate status to flush the taskfile before sampling the new state.
    status(channel);
    status(channel);
    status(channel);
    status(channel);
    clock_delay_us(1);
}

int await(Channel& channel, uint8_t required, uint8_t unset, bool check_error) {
    clock_refresh();
    const uint64_t started = ticks;
    for (unsigned i = 0; i < 4000000; ++i) {
        const uint8_t value = status(channel);
        if (!value || value == 0xff)
            return -19;
        if (!(value & busy)) {
            if (check_error && (value & (error | fault))) {
                // An ordinary command error can be retried. A protocol fault cannot.
                if (value & (fault | drq))
                    channel.failed = true;
                return -5;
            }
            if ((value & (required | unset)) == required)
                return 0;
        }
        if ((i & 255) == 255) {
            clock_refresh();
            if (ticks - started >= 500)
                break;
        }
        asm volatile("pause");
    }
    channel.failed = true;
    return -5;
}

void select(const Channel& channel, unsigned slot, uint8_t mode) {
    out8(channel.base + 6, mode | ((slot & 1) << 4));
    settle(channel);
}

void input_words(const Channel& channel, void* data) {
    size_t words = sector_size / 2;
    asm volatile("rep insw" : "+D"(data), "+c"(words) : "d"(channel.base) : "memory");
}

void output_words(const Channel& channel, const void* data) {
    size_t words = sector_size / 2;
    asm volatile("rep outsw" : "+S"(data), "+c"(words) : "d"(channel.base) : "memory");
}

void find_controller(const PciFunction& function) {
    if (function.read16(0x0a) != 0x0101 || !(function.read16(4) & 1))
        return;
    const uint8_t mode = function.read8(9);
    for (unsigned i = 0; i < 2; ++i) {
        if (mode & (1u << (2 * i)))
            continue;
        if (channels[i].enabled)
            duplicate_controller = true;
        channels[i].enabled = true;
    }
}

void identify(unsigned slot) {
    auto& channel = channels[slot / 2];
    if (!channel.enabled || channel.failed)
        return;
    out8(channel.control, disable_irq);
    select(channel, slot, 0xa0);
    const uint8_t initial = status(channel);
    if (!initial || initial == 0xff || await(channel, 0, drq, false))
        return;
    for (unsigned reg = 2; reg <= 5; ++reg)
        out8(channel.base + reg, 0);
    out8(channel.base + 7, 0xec);
    settle(channel);
    if (await(channel, drq, 0, true))
        return;
    uint16_t words[256];
    input_words(channel, words);
    settle(channel);
    if (await(channel, 0, drq, true) || (words[0] & 0x8000) || !(words[49] & 0x200))
        return;

    if ((words[106] & 0xd000) == 0x5000 && (words[117] != sector_size / 2 || words[118] != 0))
        return;

    const bool commands_valid = (words[83] & 0xc000) == 0x4000;
    const bool extended = commands_valid && (words[83] & 0x0400);
    uint64_t capacity = uint32_t(words[61]) << 16 | words[60];
    if (extended) {
        capacity = 0;
        for (unsigned i = 0; i < 4; ++i)
            capacity |= uint64_t(words[100 + i]) << (16 * i);
    }
    if (!capacity || capacity > (extended ? lba48_limit : lba28_limit))
        return;

    // Only offer writes when a cache flush can be requested explicitly.
    const uint8_t flush = commands_valid && extended && (words[83] & 0x2000) ? 0xea
                          : commands_valid && (words[83] & 0x1000)           ? 0xe7
                                                                             : 0;
    drives[slot] = {{capacity, !flush, flush != 0}, flush};
    log("ata: disk=sd%c channel=%u unit=%u sectors=%u lba48=%u flush=%u\n", int('a' + slot),
        uint64_t(slot / 2), uint64_t(slot & 1), capacity, uint64_t(extended), uint64_t(flush != 0));
}

void taskfile(const Channel& channel, uint64_t sector, uint8_t count, bool extended) {
    if (extended) {
        out8(channel.base + 1, 0);
        out8(channel.base + 2, 0);
        for (unsigned i = 0; i < 3; ++i)
            out8(channel.base + 3 + i, sector >> (24 + i * 8));
    }
    out8(channel.base + 1, 0);
    out8(channel.base + 2, count);
    for (unsigned i = 0; i < 3; ++i)
        out8(channel.base + 3 + i, sector >> (i * 8));
}

int prepare(Channel& channel, unsigned slot, uint8_t head) {
    if (channel.failed)
        return -5;
    select(channel, slot, head);
    return await(channel, ready, drq, false);
}
} // namespace

void ata_init() {
    pci_scan(find_controller);
    if (duplicate_controller) {
        log("ata: ambiguous PCI IDE compatibility channels\n");
        return;
    }
    for (unsigned slot = 0; slot < ata_device_slots; ++slot)
        identify(slot);
}

const BlockInfo* ata_info(unsigned slot) {
    return slot < ata_device_slots && drives[slot].info.sectors ? &drives[slot].info : nullptr;
}

int ata_transfer(unsigned slot, uint64_t sector, void* data, size_t count, bool write) {
    const BlockInfo* info = ata_info(slot);
    if (!info)
        return -19;
    if (sector > info->sectors || count > info->sectors - sector || count > 255)
        return -22;
    if (!count)
        return 0;
    if (write && info->readonly)
        return -30;

    auto& channel = channels[slot / 2];
    const bool extended = sector + count > lba28_limit;
    uint8_t head = extended ? 0xe0 : 0xe0 | ((sector >> 24) & 0x0f);
    if (int result = prepare(channel, slot, head))
        return result;
    taskfile(channel, sector, count, extended);
    out8(channel.base + 7, extended ? (write ? 0x34 : 0x24) : (write ? 0x30 : 0x20));
    settle(channel);
    auto* bytes = static_cast<uint8_t*>(data);
    for (size_t i = 0; i < count; ++i) {
        if (int result = await(channel, drq, 0, true))
            return result;
        if (write)
            output_words(channel, bytes);
        else
            input_words(channel, bytes);
        bytes += sector_size;
        settle(channel);
    }
    return await(channel, 0, drq, true);
}

int ata_flush(unsigned slot) {
    if (!ata_info(slot))
        return -19;
    if (!drives[slot].flush_command)
        return 0;
    auto& channel = channels[slot / 2];
    if (int result = prepare(channel, slot, 0xe0))
        return result;
    out8(channel.base + 7, drives[slot].flush_command);
    settle(channel);
    return await(channel, 0, drq, true);
}
} // namespace ax
