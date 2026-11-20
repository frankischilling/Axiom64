// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/random/seed_publication_error.c
 * @brief   Random seed publication error test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises errors while exposing an updated seed file to readers.
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
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int __real_renameat(int, const char*, int, const char*);

// Native failure fixture: the after mode performs the real Linux rename before
// reporting EIO. The before mode is a no-effect control. Neither is a disk fault.
int __wrap_renameat(int old_directory, const char* old_name, int new_directory,
                    const char* new_name) {
    const char* mode = getenv("AXIOM64_SEED_RENAME_ERROR");
    int publication = mode && !strncmp(old_name, "seed.tmp.", 9) && !strcmp(new_name, "seed");
    if (publication && !strcmp(mode, "before")) {
        puts("NATIVE_SEED_RENAME_ERROR phase=before kernel_called=0");
        errno = EIO;
        return -1;
    }
    int result = __real_renameat(old_directory, old_name, new_directory, new_name);
    if (publication && !strcmp(mode, "after") && result == 0) {
        puts("NATIVE_SEED_RENAME_ERROR phase=after kernel_called=1 kernel_result=0");
        errno = EIO;
        return -1;
    }
    return result;
}
