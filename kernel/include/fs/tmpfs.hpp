// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/tmpfs.hpp
 * @brief   Volatile filesystem mount limits.
 * @author  frankischilling
 * @date    2026-11-23
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
#include "core/base.hpp"

namespace ax {
struct FilesystemOps;
struct Mount;

struct TmpfsLimits {
    uint64_t pages, inodes;
    uint64_t used_pages = 0, used_inodes = 0;
};

extern const FilesystemOps tmpfs_ops;
TmpfsLimits* tmpfs_limits(const Mount*);
int tmpfs_mount(Mount*, const char* options);
} // namespace ax
