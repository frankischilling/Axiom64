// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/toolchain/broken.c
 * @brief   Intentional compiler diagnostic input.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Contains a syntax error for the guest toolchain's compilation failure check.
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
int main(void) { return missing_symbol( ;
}
