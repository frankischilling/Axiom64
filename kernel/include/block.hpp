// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "base.hpp"

namespace ax {
constexpr size_t sector_size = 512;
struct BlockInfo {
    uint64_t sectors;
    bool readonly, flush_supported;
};
void block_init();
const BlockInfo* block_info(unsigned device);
// Whole-sector, synchronous transfers. Validate the complete range before I/O.
// Buffers are kernel addresses; DMA uses private buffers owned by the implementation.
int block_read(unsigned device, uint64_t sector, void* data, size_t count);
int block_write(unsigned device, uint64_t sector, const void* data, size_t count,
                const void* owner = nullptr);
int block_flush(unsigned device);
int block_claim(unsigned device, const void* owner);
void block_unclaim(unsigned device, const void* owner);
bool block_claimed(unsigned device);
} // namespace ax
