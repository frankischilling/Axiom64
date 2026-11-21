// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/partition.cpp
 * @brief   Host validation of the partition decoder.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Reads independently generated disk fixtures into the production partition scanner.
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
#include "drivers/block/partition.hpp"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

using namespace ax;

namespace {
struct Input {
    FILE* disk;
    uint64_t sectors;
    uint64_t fail;
};

int read_sector(void* context, uint64_t sector, void* data) {
    auto& input = *static_cast<Input*>(context);
    assert(sector < input.sectors);
    if (sector == input.fail)
        return -5;
    assert(fseek(input.disk, long(sector * sector_size), SEEK_SET) == 0);
    assert(fread(data, 1, sector_size, input.disk) == sector_size);
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    assert(argc >= 5 && (argc - 5) % 4 == 0);
    Input input{fopen(argv[1], "rb"), strtoull(argv[2], nullptr, 10),
                strtoull(argv[3], nullptr, 10)};
    assert(input.disk);
    PartitionTable table;
    memset(&table, 0xab, sizeof(table));
    assert(read_partition_table(input.sectors, read_sector, &input, table) == atoi(argv[4]));
    unsigned found = 0;
    for (const auto& partition : table.entries)
        if (partition.sectors)
            found++;
    assert(found == unsigned((argc - 5) / 4));
    for (int i = 5; i < argc; i += 4) {
        unsigned number = unsigned(atoi(argv[i]));
        assert(number && number <= max_partitions);
        const auto& partition = table.entries[number - 1];
        assert(partition.start == strtoull(argv[i + 1], nullptr, 10));
        assert(partition.sectors == strtoull(argv[i + 2], nullptr, 10));
        assert(!strcmp(partition.id, argv[i + 3]));
        if (number == 1 && !strcmp(partition.id, "01234567-89ab-cdef-0123-456789abcdef"))
            assert(!strcmp(partition.label, "root-\xe2\x98\x83"));
    }
    assert(fclose(input.disk) == 0);
}
