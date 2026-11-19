// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/proc.hpp
 * @brief   Procfs filesystem interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares procfs root creation and the operations exposed to the virtual
 * filesystem.
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
#include "fs/vfs.hpp"

namespace ax {
extern const FilesystemOps procfs_ops;
Node* procfs_root(Mount*);
bool procfs_has_poll(const Node&);
} // namespace ax
