// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/boot/root.hpp
 * @brief   Root filesystem setup.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the boot-time root volume and init ramdisk setup interface.
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

namespace ax {
class BootArguments;
// Select and validate the root before starting Ring 3 init.
void boot_root_init(const BootArguments& arguments, const char* init);
} // namespace ax
