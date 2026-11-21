// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/block.hpp
 * @brief   Block device interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the sector I/O interface used by storage drivers and mounted
 * filesystems.
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
#include "core/base.hpp"

namespace ax {
constexpr size_t sector_size = 512;
constexpr size_t block_name_size = sizeof("/dev/vdh128");

struct BlockInfo {
    uint64_t sectors;
    bool readonly, flush_supported;
};

void block_init();

const BlockInfo* block_info(unsigned device);

unsigned block_device_limit();

void block_device_name(unsigned device, char (&name)[block_name_size]);

uint64_t block_device_number(unsigned device);

int block_find(const char* selection);

// Whole-sector, synchronous transfers. Validate the complete range before I/O.
// Buffers are kernel addresses; DMA uses private buffers owned by the implementation.
int block_read(unsigned device, uint64_t sector, void* data, size_t count);

// The claim owns the cache. Reads that do not match its block geometry bypass it.
int block_enable_cache(unsigned device, unsigned sectors_per_block, const void* owner);

int block_read_cached(unsigned device, uint64_t sector, void* data, size_t count);

uint64_t block_buffer_bytes();

int block_write(unsigned device, uint64_t sector, const void* data, size_t count,
                const void* owner = nullptr);

int block_flush(unsigned device);

int block_claim(unsigned device, const void* owner);

void block_unclaim(unsigned device, const void* owner);

bool block_claimed(unsigned device);
} // namespace ax
