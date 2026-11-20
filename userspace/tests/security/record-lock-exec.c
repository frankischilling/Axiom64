// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/security/record-lock-exec.c
 * @brief   Byte-range lock exec test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks lock ownership when the process replaces its executable image.
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
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

// A separate executable proves that the lock observations happen after exec.
// The parent inspects the inode from a different file table before allowing exit.
int main(int argc, char** argv) {
    if (argc != 4)
        return 1;
    int file = atoi(argv[1]), ready = atoi(argv[2]), finish = atoi(argv[3]);
    char byte = 'x';
    if (fcntl(file, F_GETFD) < 0 || write(ready, &byte, 1) != 1 || read(finish, &byte, 1) != 1 ||
        byte != 'x')
        return 1;
    return 0;
}
