// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/toolchain/hello.c
 * @brief   Guest C toolchain smoke test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Provides a small C program to compile, link, and execute on the guest.
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
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int* values = malloc(100 * sizeof(int));
    if (!values)
        return 1;
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        values[i] = i;
        sum += values[i];
    }
    free(values);
    if (sum != 4950)
        return 2;
    puts("NATIVE_C_PASS");
    return 0;
}
