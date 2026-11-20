// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/ext2/xattr.hpp
 * @brief   Ext2 extended-attribute block interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the ext2 attribute block encoding and validation interfaces.
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
#include "fs/xattr.hpp"

namespace ax {
bool ext2_xattr_valid(const void*, size_t, uint32_t& references);
bool ext2_xattr_supported(const void*, size_t);
int64_t ext2_xattr_get(const void*, size_t, const XattrName&, void*, size_t);
int64_t ext2_xattr_list(const void*, size_t, void*, size_t, bool trusted);
// Build a complete private replacement block before the filesystem stages it.
// The source and destination must be distinct; a null source means no attributes.
int ext2_xattr_change(const void*, size_t, const XattrName&, const void*, size_t, unsigned flags,
                      bool remove, void*, bool& empty);
} // namespace ax
