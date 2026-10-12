// SPDX-License-Identifier: GPL-3.0-or-later
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
