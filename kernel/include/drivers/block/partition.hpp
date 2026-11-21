// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/partition.hpp
 * @brief   Bounded partition discovery.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Describes partition spans and makes the decoder independent of the disk transport.
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
#include "drivers/block/block.hpp"

namespace ax {
constexpr unsigned max_partitions = 128;
constexpr size_t partition_label_size = 109;

struct Partition {
    uint64_t start, sectors;
    char id[37], label[partition_label_size];
};

struct PartitionTable {
    Partition entries[max_partitions];
};

using ReadPartitionSector = int (*)(void*, uint64_t, void*);

// Zero means successful discovery (including an unpartitioned disk).
// On failure the table is empty. The reader supplies one complete 512-byte sector.
int read_partition_table(uint64_t sectors, ReadPartitionSector read, void* context,
                         PartitionTable& table);
} // namespace ax
