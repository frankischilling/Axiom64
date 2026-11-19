// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/init/seed_records.h
 * @brief   Init test record interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the helpers used to report structured seed and test records from
 * init.
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
#include <stdio.h>
#include <unistd.h>

static inline void init_seed_write_record(const char* record, int size, size_t capacity) {
    if (size <= 0 || (size_t)size >= capacity)
        return;
    fflush(stdout);
    // Keep the newline and complete event together during asynchronous console echo.
    ssize_t written = write(STDOUT_FILENO, record, (size_t)size);
    (void)written;
}

static inline void init_seed_spawned_record(int child, unsigned long long milliseconds) {
    char record[128];
    int size = snprintf(record, sizeof(record),
                        "\nINIT_RANDOM_SEED_SPAWN pid=%d monotonic_ms=%llu\n", child, milliseconds);
    init_seed_write_record(record, size, sizeof(record));
}

static inline void init_seed_reaped_record(int child, int status, unsigned long long milliseconds) {
    char record[128];
    int size = snprintf(record, sizeof(record),
                        "\nINIT_RANDOM_SEED_REAP pid=%d status=%d monotonic_ms=%llu\n", child,
                        status, milliseconds);
    init_seed_write_record(record, size, sizeof(record));
}
