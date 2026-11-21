// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/floppy.cpp
 * @brief   Primary ISA floppy disk driver.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Transfers sectors through channel 2 DMA and checks the controller result phase.
 * Supports fixed 1.44 MB media and shuts down idle drive motors.
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
#include "drivers/block/floppy.hpp"
#include "mm/dma.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
constexpr uint16_t dor = 0x3f2, msr = 0x3f4, fifo = 0x3f5, dir = 0x3f7;
constexpr uint8_t awake = 0x0c;
constexpr uint8_t rqm = 0x80, dio = 0x40, non_dma = 0x20;
constexpr unsigned heads = 2, sectors_per_track = 18, cylinders = 80;
constexpr unsigned capacity = heads * sectors_per_track * cylinders;
constexpr Dma::Limits dma_limits{1u << 24, 1u << 16};
constexpr uint8_t dma_channel = 2, dma_masked = 4 | dma_channel;
constexpr uint16_t dma_mask = 0x0a, dma_flip_flop = 0x0c, dma_count = 0x05;
static_assert(page_size >= sector_size && 0x10000 % page_size == 0);

struct Drive {
    BlockInfo info{};
    int cylinder = -1;
    uint64_t activity = 0;
    bool media_changed = false;
};

Drive drives[floppy_slots];
uint64_t dma_page;
unsigned selected;
uint8_t motors;
bool initialized;

uint64_t now() {
    clock_refresh();
    return ticks;
}

bool elapsed(uint64_t start, unsigned centiseconds) {
    return now() - start >= centiseconds;
}

template <typename Test> bool wait(Test condition, unsigned centiseconds) {
    uint64_t start = now();
    for (unsigned spin = 0; spin < 20000000; ++spin) {
        if (condition())
            return true;
        if ((spin & 127) == 127 && elapsed(start, centiseconds))
            break;
        asm volatile("pause");
    }
    return false;
}

bool write_command(const uint8_t* bytes, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (!wait([] { return (in8(msr) & (rqm | dio | non_dma)) == rqm; }, 100))
            return false;
        out8(fifo, bytes[i]);
    }
    return true;
}

bool read_result(uint8_t& byte) {
    if (!wait([] { return (in8(msr) & (rqm | dio | non_dma)) == (rqm | dio); }, 100))
        return false;
    byte = in8(fifo);
    return true;
}

bool sense(uint8_t& state, uint8_t& cylinder) {
    const uint8_t command = 0x08;
    return write_command(&command, 1) && read_result(state) &&
           (state == 0x80 || read_result(cylinder));
}

void reset() {
    out8(dma_mask, dma_masked);
    out8(dor, 0);
    motors = 0;
    initialized = false;
    for (auto& drive : drives)
        drive.cylinder = -1;
}

bool configure() {
    if (initialized)
        return true;
    reset();
    if (!clock_delay_us(10))
        return false;
    out8(dor, awake);
    for (unsigned i = 0; i < 4; ++i) {
        uint8_t state, cylinder;
        if (!sense(state, cylinder))
            return false;
        if (state == 0x80)
            break;
    }
    out8(dir, 0); // 500 kbit/s.
    const uint8_t specify[]{0x03, 0xdf, 0x02};
    const uint8_t parameters[]{0x13, 0, 0x17, 0}; // FIFO enabled, explicit seek, no drive polling.
    initialized =
        write_command(parameters, sizeof(parameters)) && write_command(specify, sizeof(specify));
    return initialized;
}

bool activate(unsigned unit) {
    if (!configure())
        return false;
    const uint8_t motor = 0x10 << unit;
    const bool warm = motors & motor;
    selected = unit;
    motors |= motor;
    out8(dor, awake | motors | unit);
    if (!warm) {
        const uint64_t start = now();
        if (!wait([start] { return elapsed(start, 50); }, 100))
            return false;
    }
    drives[unit].activity = now();
    return true;
}

bool seek(unsigned unit, unsigned head, unsigned cylinder, bool recalibrate) {
    const uint8_t drive = unit | (head << 2);
    const uint8_t command[]{uint8_t(recalibrate ? 0x07 : 0x0f), drive, uint8_t(cylinder)};
    if (!write_command(command, recalibrate ? 2 : 3))
        return false;

    uint8_t state = 0x80, reached = 0xff;
    const bool finished = wait(
        [&] {
            if (in8(msr) & (1u << unit))
                return false;
            return !sense(state, reached) || state != 0x80;
        },
        200);
    return finished && (state & 0xe3) == (0x20 | unit) && reached == cylinder;
}

bool position(unsigned unit, unsigned head, unsigned cylinder) {
    auto& drive = drives[unit];
    if (drive.cylinder < 0) {
        if (!seek(unit, 0, 0, true))
            return false;
        drive.cylinder = 0;
    }
    if (unsigned(drive.cylinder) != cylinder) {
        if (!seek(unit, head, cylinder, false))
            return false;
        drive.cylinder = cylinder;
    }
    return true;
}

void start_dma(bool write) {
    constexpr unsigned count = sector_size - 1;
    out8(dma_mask, dma_masked);
    out8(dma_flip_flop, 0);
    out8(0x04, dma_page);
    out8(0x04, dma_page >> 8);
    out8(0x81, dma_page >> 16);
    out8(dma_flip_flop, 0);
    out8(dma_count, uint8_t(count));
    out8(dma_count, count >> 8);
    out8(0x0b, write ? 0x4a : 0x46);
    asm volatile("" ::: "memory");
    out8(dma_mask, dma_channel);
}

bool dma_complete() {
    out8(dma_flip_flop, 0);
    const uint8_t low = in8(dma_count);
    const uint8_t high = in8(dma_count);
    return low == 0xff && high == 0xff;
}

int sector_io(unsigned unit, uint64_t lba, void* data, bool write) {
    const unsigned track = lba / sectors_per_track;
    const unsigned head = track % heads;
    const unsigned cylinder = track / heads;
    const uint8_t sector = (lba % sectors_per_track) + 1;
    if (!activate(unit)) {
        reset();
        return -5;
    }
    auto& drive = drives[unit];
    if (drive.info.sectors && (drive.media_changed || (in8(dir) & 0x80))) {
        if (!drive.media_changed)
            log("floppy: fd%u media changed, reboot to reattach\n", uint64_t(unit));
        drive.media_changed = true;
        return -5;
    }
    if (!position(unit, head, cylinder)) {
        reset();
        return -5;
    }
    const uint8_t command[]{uint8_t(write ? 0x45 : 0x46),
                            uint8_t(unit | (head << 2)),
                            uint8_t(cylinder),
                            uint8_t(head),
                            sector,
                            2,
                            sector,
                            0x1b,
                            0xff};
    auto bounce = physical(dma_page);
    if (write)
        memcpy(bounce, data, sector_size);
    start_dma(write);
    bool valid = write_command(command, sizeof(command));
    uint8_t result[7];
    for (auto& byte : result)
        valid = valid && read_result(byte);
    out8(dma_mask, dma_masked);
    asm volatile("" ::: "memory");
    if (!valid) {
        reset();
        return -5;
    }
    if (result[1] & 2)
        return -30;
    if ((result[0] & 0xc3) != unit || result[1] || result[2] || result[6] != 2 || !dma_complete()) {
        drives[unit].cylinder = -1;
        return -5;
    }
    if (!write)
        memcpy(data, bounce, sector_size);
    drives[unit].activity = now();
    return 0;
}
} // namespace

void floppy_init() {
    out8(0x70, 0x10);
    const uint8_t types = in8(0x71);
    if ((types >> 4) != 4 && (types & 15) != 4)
        return;
    if (in8(msr) == 0xff)
        return;
    dma_page = Dma::allocate(1, dma_limits);
    if (!dma_page) {
        log("floppy: no ISA DMA page available\n");
        return;
    }
    uint8_t scratch[sector_size];
    for (unsigned unit = 0; unit < floppy_slots; ++unit) {
        if (((types >> (unit ? 0 : 4)) & 15) != 4)
            continue;
        if (sector_io(unit, capacity - 1, scratch, false))
            continue;
        const uint8_t command[]{0x04, uint8_t(unit)};
        uint8_t status;
        if (!write_command(command, sizeof(command)) || !read_result(status) ||
            (status & 3) != unit) {
            reset();
            continue;
        }
        drives[unit].info = {capacity, bool(status & 0x40), false};
        log("floppy: fd%u sectors=%u readonly=%u DMA=%x\n", uint64_t(unit), uint64_t(capacity),
            uint64_t(drives[unit].info.readonly), dma_page);
    }
    if (!floppy_info(0) && !floppy_info(1)) {
        reset();
        page_free(dma_page, 1);
        dma_page = 0;
    }
}

const BlockInfo* floppy_info(unsigned unit) {
    return unit < floppy_slots && drives[unit].info.sectors ? &drives[unit].info : nullptr;
}

int floppy_transfer(unsigned unit, uint64_t sector, void* data, size_t count, bool write) {
    const auto* info = floppy_info(unit);
    if (!info)
        return -19;
    if (drives[unit].media_changed)
        return -5;
    if (sector > capacity || count > capacity - sector)
        return -22;
    if (write && info->readonly)
        return -30;
    auto bytes = static_cast<uint8_t*>(data);
    for (size_t i = 0; i < count; ++i)
        if (int result = sector_io(unit, sector + i, bytes + i * sector_size, write))
            return result;
    return 0;
}

void floppy_poll() {
    if (!motors)
        return;
    uint8_t previous = motors;
    for (unsigned unit = 0; unit < floppy_slots; ++unit)
        if ((motors & (0x10 << unit)) && elapsed(drives[unit].activity, 200))
            motors &= ~(0x10 << unit);
    if (motors != previous)
        out8(dor, awake | motors | selected);
}
} // namespace ax
